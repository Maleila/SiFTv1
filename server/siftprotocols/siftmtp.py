# python3

import socket
import Crypto.Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import getpass
import sys


class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg


class SiFT_MTP:
    def __init__(self, peer_socket):

        self.DEBUG = True
        # --------- CONSTANTS ------------
        self.version_major = 0
        self.version_minor = 5
        self.msg_hdr_ver = b'\x01\x00'
        self.size_msg_hdr = 16
        self.size_msg_hdr_ver = 2
        self.size_msg_hdr_typ = 2
        self.size_msg_hdr_len = 2
        self.size_msg_hdr_sqn = 2
        self.size_msg_hdr_rnd = 6
        self.size_msg_hdr_rsv = 2
        self.mac_size = 12
        self.type_login_req = b'\x00\x00'
        self.type_login_res = b'\x00\x10'
        self.type_command_req = b'\x01\x00'
        self.type_command_res = b'\x01\x10'
        self.type_upload_req_0 = b'\x02\x00'
        self.type_upload_req_1 = b'\x02\x01'
        self.type_upload_res = b'\x02\x10'
        self.type_dnload_req = b'\x03\x00'
        self.type_dnload_res_0 = b'\x03\x10'
        self.type_dnload_res_1 = b'\x03\x11'
        self.rsv_val = b'\x00\x00'
        self.AES_key = b''
        self.sqn_rcv = 0  # turned into bytes when needed - easier to increment as an int
        self.sqn_snd = 0
        self.msg_types = (self.type_login_req, self.type_login_res,
                          self.type_command_req, self.type_command_res,
                          self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
                          self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
        # --------- STATE ------------
        self.peer_socket = peer_socket

    # parsed a message header and returned a dictionary containing the header fields
    def parse_msg_header(self, msg_hdr):

        parsed_msg_hdr, i = {}, 0
        parsed_msg_hdr['ver'], i = msg_hdr[i:i +
                                           self.size_msg_hdr_ver], i+self.size_msg_hdr_ver
        parsed_msg_hdr['typ'], i = msg_hdr[i:i +
                                           self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
        parsed_msg_hdr['len'], i = msg_hdr[i:i +
                                           self.size_msg_hdr_len], i+self.size_msg_hdr_len
        parsed_msg_hdr['sqn'], i = msg_hdr[i:i +
                                           self.size_msg_hdr_sqn], i+self.size_msg_hdr_sqn
        parsed_msg_hdr['rnd'], i = msg_hdr[i:i +
                                           self.size_msg_hdr_rnd], i+self.size_msg_hdr_rnd
        parsed_msg_hdr['rsv'], i = msg_hdr[i:i +
                                           self.size_msg_hdr_rsv], i+self.size_msg_hdr_rsv
        return parsed_msg_hdr

    # receives n bytes from the peer socket
    def receive_bytes(self, n):

        bytes_received = b''
        bytes_count = 0
        while bytes_count < n:
            try:
                chunk = self.peer_socket.recv(n-bytes_count)
            except:
                raise SiFT_MTP_Error('Unable to receive via peer socket')
            if not chunk:
                raise SiFT_MTP_Error('Connection with peer is broken')
            bytes_received += chunk
            bytes_count += len(chunk)
        return bytes_received

    #decrypts with AES and current key, as well as decrypting temporary key with RSA for login requests
    def decrypt_payload(self, msg_hdr, parsed_msg_hdr, msg):

        # if this is a login request, decrypt the encrypted temporary key
        if parsed_msg_hdr['typ'] == self.type_login_req:
            etk = msg[-256:]

            # read in keypair
            with open("keypair.pem", 'rb') as f:
                keypairstr = f.read()
            try:
                RSAcipher = PKCS1_OAEP.new(RSA.import_key(
                    keypairstr))
            except ValueError:
                print('Error: Cannot import private key from file keypair.pem')
                sys.exit(1)

            tk = RSAcipher.decrypt(etk)
            self.AES_key = tk
            # if this is a login request, have to account for the size 
            # of the etk when grabbing the mac and encrypted payload
            mac = msg[-256-self.mac_size:-256]
            encrypted_payload = msg[:-256-self.mac_size]
        else:
            mac = msg[-self.mac_size:]
            encrypted_payload = msg[:-self.mac_size]
            # print(f"mac: {len(mac)}", mac.hex())
            # print("received encryption: ", encrypted_payload.hex())
            # print("header: ", msg_hdr.hex())
            # print("key:", self.AES_key.hex()

        # DEBUG
        if self.DEBUG:
            print('MTP message received:')
            print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
            print('EPD (' + str(len(encrypted_payload)) + '): ' + encrypted_payload.hex())
            print('MAC (' + str(len(mac)) + '): ' + mac.hex())
            if parsed_msg_hdr['typ'] == self.type_login_req:
                print('ETK (' + str(len(etk)) + '): '+ etk.hex())
            
        print('------------------------------------------')
            

        nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']
        cipher = AES.new(self.AES_key, AES.MODE_GCM, nonce=nonce, mac_len=12)
        cipher.update(msg_hdr)
        try:
            decrypted_payload = cipher.decrypt_and_verify(
                encrypted_payload, mac)
        except ValueError as e:
            raise SiFT_MTP_Error('MAC verification failed: ' + str(e))

        if parsed_msg_hdr['typ'] == self.type_login_req:
            self.set_key(tk)

        return decrypted_payload

    # receives and parses message, returns msg_type and msg_payload
    def receive_msg(self):
        try:
            msg_hdr = self.receive_bytes(self.size_msg_hdr)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error(
                'Unable to receive message header --> ' + e.err_msg)

        if len(msg_hdr) != self.size_msg_hdr:
            raise SiFT_MTP_Error('Incomplete message header received')

        parsed_msg_hdr = self.parse_msg_header(msg_hdr)

        if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
            raise SiFT_MTP_Error('Unsupported version found in message header')

        if parsed_msg_hdr['typ'] not in self.msg_types:
            raise SiFT_MTP_Error(
                'Unknown message type found in message header')

        # validate sequence number
        if parsed_msg_hdr['sqn'] <= self.sqn_rcv.to_bytes(2, 'big'):
            raise SiFT_MTP_Error(
                'Message sequence number error')

        if parsed_msg_hdr['rsv'] != self.rsv_val:
            raise SiFT_MTP_Error(
                'Unknown reserved value found in message header')

        msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

        try:
            msg_body = self.receive_bytes(
                msg_len - self.size_msg_hdr)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error(
                'Unable to receive message body --> ' + e.err_msg)

        if len(msg_body) != msg_len - self.size_msg_hdr:
            raise SiFT_MTP_Error('Incomplete message body reveived')

        # verify mac and decrypt the payload
        decrypted_payload = self.decrypt_payload(
            msg_hdr, parsed_msg_hdr, msg_body)
        
        # update receiving sequence number after successfully receiving a message
        self.sqn_rcv += 1

        return parsed_msg_hdr['typ'], decrypted_payload

    # sends all bytes provided via the peer socket
    def send_bytes(self, bytes_to_send):
        try:
            self.peer_socket.sendall(bytes_to_send)
        except:
            raise SiFT_MTP_Error('Unable to send via peer socket')

    # builds a message header (for all message types)
    def build_msg_hdr(self, msg_type, msg_payload):
        msg_size = self.size_msg_hdr + \
            len(msg_payload) + self.mac_size
        if msg_type == self.type_login_req:
            msg_size += 256  # account for etk in login request
        msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
        msg_hdr_sqn = (self.sqn_snd+1).to_bytes(2, "big")  # use sqn_snd++
        msg_hdr_rnd = Crypto.Random.get_random_bytes(
            6)
        msg_hdr_rsv = self.rsv_val
        msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + \
            msg_hdr_sqn + msg_hdr_rnd + msg_hdr_rsv
        return msg_hdr

    # encrypts payload and produces mac (for all message types)
    def encrypt_payload(self, msg_hdr, msg_payload):
        parsed_msg_hdr = self.parse_msg_header(msg_hdr)

        if (parsed_msg_hdr['typ'] == self.type_login_req):
            # temporary key
            tk = Crypto.Random.get_random_bytes(32)
            # save this temporary key so it can be used by the client later to decrypt login response
            self.AES_key = tk

            # encrypt temporary key
            #with open("pubkey.pem", 'rb') as f:
            with open("server_pubkey.pem", 'rb') as f:
                pubkeystr = f.read()
            pubkey = RSA.import_key(pubkeystr)
            RSAcipher = PKCS1_OAEP.new(pubkey)
            etk = RSAcipher.encrypt(tk)


        # common steps
        nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']
        cipher = AES.new(self.AES_key, AES.MODE_GCM, nonce=nonce, mac_len=12)
        cipher.update(msg_hdr)
        epd, mac = cipher.encrypt_and_digest(msg_payload)

        # print("mac: ", mac.hex())
        # print("received encryption: ", epd.hex())
        # print("header: ", msg_hdr.hex())
        # print("temp key", self.AES_key.hex())

        # DEBUG
        if self.DEBUG:
            print('MTP message to send:')
            print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
            print('EPD (' + str(len(epd)) + '): ' + epd.hex())
            print('MAC (' + str(len(mac)) + '): ' + mac.hex())
            if parsed_msg_hdr['typ'] == self.type_login_req:
                print('ETK (' + str(len(etk)) + '): '+ etk.hex())
            
        print('------------------------------------------')

        if (parsed_msg_hdr['typ'] == self.type_login_req):
            return epd + mac + etk
        else:
            return epd + mac

    # sends message
    def send_msg(self, msg_type, msg_payload):
        msg_hdr = self.build_msg_hdr(msg_type, msg_payload)
        msg_body = self.encrypt_payload(msg_hdr, msg_payload)
        msg = msg_hdr + msg_body

        # try to send
        try:
            self.send_bytes(msg)
            self.sqn_snd += 1
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error(
                'Unable to send message to peer --> ' + e.err_msg)

    # change from temporary key to final transfer key
    def set_key(self, key):
        self.AES_key = key
        # print("key change (client side)")
