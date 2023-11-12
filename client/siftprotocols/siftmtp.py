# python3

import socket
import Crypto.Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA


class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg


class SiFT_MTP:
    def __init__(self, peer_socket):

        self.DEBUG = True
        # --------- CONSTANTS ------------
        self.version_major = 0
        self.version_minor = 5
        self.msg_hdr_ver = b'\x00\x05'
        self.size_msg_hdr = 16
        self.size_msg_hdr_ver = 2
        self.size_msg_hdr_typ = 2
        self.size_msg_hdr_len = 2
        self.size_msg_hdr_sqn = 2
        self.size_msg_hdr_rnd = 6
        self.size_msg_hdr_rsv = 2
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
        self.rsv_val = b'00'
        self.msg_types = (self.type_login_req, self.type_login_res,
                          self.type_command_req, self.type_command_res,
                          self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
                          self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
        # --------- STATE ------------
        self.peer_socket = peer_socket
        key = ""

    # parses a message header and returns a dictionary containing the header fields

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
        parsed_msg_hdr['rsv'], i = msg_hdr[i:i+self.size_msg_hdr_rsv], i+self.size_msg_hdr_rsv
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

    def process_login_req(self, msg_hdr, msg):
        etk = msg[-256:]
        with open("keypair.pem", 'rb') as f:
            keypairstr = f.read()
        RSAcipher = PKCS1_OAEP.new(RSA.import_key(keypairstr))
        tk = RSAcipher.decrypt(etk)

        nonce = msg_hdr['sqn'] + msg_hdr['rnd']
        cipher = AES.new(tk, AES.MODE_GCM, nonce)
        try:
            decrypted_payload = cipher.decrypt_and_verify(msg[16:-256])
        except ValueError as e:
            raise SiFT_MTP_Error('MAC verification failed')
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
        
        print(parsed_msg_hdr['sqn'])

        if parsed_msg_hdr['typ'] == self.type_login_req:
            if parsed_msg_hdr['sqn'] != b'01':
                raise SiFT_MTP_Error(
                'Message sequence number error')

        if parsed_msg_hdr['rsv'] != self.rsv_val:
            raise SiFT_MTP_Error(
                'Unknown reserved value found in message header')

        msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

        try:
            msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error(
                'Unable to receive message body --> ' + e.err_msg)

        # DEBUG
        if self.DEBUG:
            print('MTP message received (' + str(msg_len) + '):')
            print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
            print('BDY (' + str(len(msg_body)) + '): ')
            print(msg_body.hex())
            print('------------------------------------------')
        # DEBUG

        if len(msg_body) != msg_len - self.size_msg_hdr:
            raise SiFT_MTP_Error('Incomplete message body reveived')

        #return parsed_msg_hdr['typ'], msg_body
        return parsed_msg_hdr, msg_body

    # sends all bytes provided via the peer socket
    def send_bytes(self, bytes_to_send):
        try:
            self.peer_socket.sendall(bytes_to_send)
        except:
            raise SiFT_MTP_Error('Unable to send via peer socket')

    #builds a login request (used by client)
    def build_login_req(self, msg_payload):
        # probably shouldn't hardcode the last 2 lengths
        msg_size = self.size_msg_hdr + len(msg_payload) + 12 + 256
        msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
        msg_hdr_sqn = b'01'
        msg_hdr_rnd = Crypto.Random.get_random_bytes(
            6)
        msg_hdr_rsv = b'00'
        msg_hdr = self.msg_hdr_ver + self.type_login_req + msg_hdr_len + \
            msg_hdr_sqn + msg_hdr_rnd + msg_hdr_rsv

        #actually this is probably supposed to be the final transfer key from the login protocol
        tk = Crypto.Random.get_random_bytes(32)
        nonce = msg_hdr_sqn + msg_hdr_rnd
        cipher = AES.new(tk, AES.MODE_GCM, nonce)
        cipher.update(msg_hdr+msg_payload)
        epd, mac = cipher.encrypt_and_digest(msg_payload)
        print('mac: ' + str(len(mac)))  # should be 12, come back to this

        # encrypt temporary key
        with open("pubkey.pem", 'rb') as f:
            pubkeystr = f.read()
        RSAcipher = PKCS1_OAEP.new(RSA.import_key(pubkeystr))
        etk = RSAcipher.encrypt(tk)
        print(len(etk))

        return msg_hdr + epd + mac + etk

    # builds a login response (used by the server)
    def build_login_res(self, msg_payload):
        msg_size = self.size_msg_hdr + len(msg_payload)
        msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
        msg_hdr_sqn = 1
        msg_hdr_rnd = str(Crypto.Random.get_random_bytes(
            6))
        msg_hdr_rsv = b'00'
        msg_hdr = self.msg_hdr_ver + self.type_login_res + msg_hdr_len + \
            msg_hdr_sqn + msg_hdr_rnd + msg_hdr_rsv

    #builds a standard message
    def build_msg(self, msg_type, msg_payload):
        msg_size = self.size_msg_hdr + len(msg_payload)
        msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
        msg_hdr_sqn = 0  # edit this later w actual sequence numbers
        msg_hdr_rnd = str(Crypto.Random.get_random_bytes(
            6))
        msg_hdr_rsv = b'00'
        msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + \
            msg_hdr_sqn + msg_hdr_rnd + msg_hdr_rsv
        return msg_hdr+msg_payload

    #sends message
    def send_msg(self, msg_type, msg_payload):
        if msg_type == self.type_login_req:
            msg = self.build_login_req(msg_payload)
        elif msg_type == self.type_login_res:
            msg = self.build_login_res(msg_payload)
        else:
            msg = self.build_msg(msg_type, msg_payload)

        # DEBUG
        if self.DEBUG:
            # print('MTP message to send (' + str(len(msg_hdr)) + '):')
            # print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
            print('BDY (' + str(len(msg_payload)) + '): ')
            print(msg_payload.hex())
            print('------------------------------------------')
        # DEBUG

        # try to send
        try:
            self.send_bytes(msg)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error(
                'Unable to send message to peer --> ' + e.err_msg)

    def set_key(self, new_key):
        self.key = new_key
