import sys
import getopt
import getpass
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util import Padding
from Crypto import Random


def save_publickey(pubkey):
    with open("pubkey.pem", 'wb') as f:
        f.write(pubkey.export_key(format='PEM'))


# def load_publickey():
#     with open("pubkey.pem", 'rb') as f:
#         pubkeystr = f.read()
#     try:
#         return RSA.import_key(pubkeystr)
#     except ValueError:
#         print('Error: Cannot import public key from file ')
#         sys.exit(1)


def save_keypair(keypair):
    # passphrase = getpass.getpass(
    #     'Enter a passphrase to protect the saved private key: ')
    with open("keypair.pem", 'wb') as f:
        f.write(keypair.export_key(format='PEM'))


def load_keypair(privkeyfile):
    passphrase = getpass.getpass(
        'Enter a passphrase to decode the saved private key: ')
    with open(privkeyfile, 'rb') as f:
        keypairstr = f.read()
    try:
        return RSA.import_key(keypairstr, passphrase=passphrase)
    except ValueError:
        print('Error: Cannot import private key from file ' + privkeyfile)
        sys.exit(1)


def newline(s):
    return s + b'\n'

# -------------------
# key pair generation
# -------------------


def KEY_PAIR_GENERATION():
    print('Generating a new 2048-bit RSA key pair...')
    keypair = RSA.generate(2048)
    save_publickey(keypair.publickey())
    save_keypair(keypair)
    print('Done.')

# ----------
# encryption
# ----------


# def ENCRYPT(pubkey, plaintext):
#     print('Encrypting...')

#     RSAcipher = PKCS1_OAEP.new(pubkey)
#     # might need to change the block size
#     padded_plaintext = Padding.pad(plaintext, AES.block_size, style='pkcs7')
#     cipherText = RSAcipher.encrypt(padded_plaintext)
#     return cipherText


# def ENCRYPTION(pubkeyfile, pubkey, privkeyfile, inputfile, outputfile, sign):
#     print('Encrypting...')

#     # load the public key from the public key file and
#     # create an RSA cipher object
#     pubkey = load_publickey(pubkeyfile)
#     RSAcipher = PKCS1_OAEP.new(pubkey)

#     # read the plaintext from the input file
#     with open(inputfile, 'rb') as f:
#         plaintext = f.read()

#     # apply PKCS7 padding on the plaintext
#     padded_plaintext = Padding.pad(plaintext, AES.block_size, style='pkcs7')

#     # generate a random symmetric key and a random IV
#     # and create an AES cipher object
#     symkey = Random.get_random_bytes(32)  # we use a 256 bit (32 byte) AES key
#     AEScipher = AES.new(symkey, AES.MODE_CBC)
#     iv = AEScipher.iv

#     # encrypt the padded plaintext with the AES cipher
#     ciphertext = AEScipher.encrypt(padded_plaintext)

#     # encrypt the AES key with the RSA cipher
#     encsymkey = RSAcipher.encrypt(symkey)

#     # compute signature if needed
#     if sign:
#         keypair = load_keypair(privkeyfile)
#         signer = pss.new(keypair)
#         hashfn = SHA256.new()
#         hashfn.update(encsymkey+iv+ciphertext)
#         signature = signer.sign(hashfn)

#     # write out the encrypted AES key, the IV, the ciphertext, and the signature
#     with open(outputfile, 'wb') as f:
#         f.write(newline(b'--- ENCRYPTED AES KEY ---'))
#         f.write(newline(b64encode(encsymkey)))
#         f.write(newline(b'--- IV FOR CBC MODE ---'))
#         f.write(newline(b64encode(iv)))
#         f.write(newline(b'--- CIPHERTEXT ---'))
#         f.write(newline(b64encode(ciphertext)))
#         if sign:
#             f.write(newline(b'--- SIGNATURE ---'))
#             f.write(newline(b64encode(signature)))

#     print('Done.')

# # ----------
# # decryption
# # ----------


# def DECRYPT(keypair, ciphertext):
#     print('Decrypting...')

#     RSAcipher = PKCS1_OAEP.new(keypair)
#     padded_plaintext = RSAcipher.decrypt(ciphertext)
#     plaintext = Padding.unpad(padded_plaintext, AES.block_size, style='pkcs7')
#     return plaintext


# def DECRYPTION(pubkeyfile, pubkey, privkeyfile, inputfile, outputfile):
#     print('Decrypting...')

#     # read and parse the input
#     encsymkey = b''
#     iv = b''
#     ciphertext = b''

#     with open(inputfile, 'rb') as f:
#         sep = f.readline()
#         while sep:
#             data = f.readline()
#             data = data[:-1]   # removing \n from the end
#             sep = sep[:-1]     # removing \n from the end

#             if sep == b'--- ENCRYPTED AES KEY ---':
#                 encsymkey = b64decode(data)
#             elif sep == b'--- IV FOR CBC MODE ---':
#                 iv = b64decode(data)
#             elif sep == b'--- CIPHERTEXT ---':
#                 ciphertext = b64decode(data)
#             elif sep == b'--- SIGNATURE ---':
#                 signature = b64decode(data)
#                 sign = True

#             sep = f.readline()

#     if (not encsymkey) or (not iv) or (not ciphertext):
#         print('Error: Could not parse content of input file ' + inputfile)
#         sys.exit(1)

#     if sign and (not pubkeyfile):
#         print('Error: Public key file is missing for  ' + inputfile)
#         sys.exit(1)

#     # verify signature if needed
#     if sign:
#         if not pubkeyfile:
#             print('Error: Public key file is missing, signature cannot be verified.')
#         else:
#             pubkey = load_publickey(pubkeyfile)
#             verifier = pss.new(pubkey)
#             hashfn = SHA256.new()
#             hashfn.update(encsymkey+iv+ciphertext)
#             try:
#                 verifier.verify(hashfn, signature)
#                 print('Signature verification is successful.')
#             except (ValueError, TypeError):
#                 print('Signature verification is failed.')
#                 yn = input('Do you want to continue (y/n)? ')
#                 if yn != 'y':
#                     sys.exit(1)

#     # load the private key from the private key file and
#     # create the RSA cipher object
#     keypair = load_keypair(privkeyfile)
#     RSAcipher = PKCS1_OAEP.new(keypair)

#     # decrypt the AES key and create the AES cipher object
#     symkey = RSAcipher.decrypt(encsymkey)
#     AEScipher = AES.new(symkey, AES.MODE_CBC, iv)

#     # decrypt the ciphertext and remove padding
#     padded_plaintext = AEScipher.decrypt(ciphertext)
#     plaintext = Padding.unpad(padded_plaintext, AES.block_size, style='pkcs7')

#     # write out the plaintext into the output file
#     with open(outputfile, 'wb') as f:
#         f.write(plaintext)

#     print('Done.')


KEY_PAIR_GENERATION()
