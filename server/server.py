# python3

import sys
import threading
import socket
import getpass
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error
from siftprotocols.siftlogin import SiFT_LOGIN, SiFT_LOGIN_Error
from siftprotocols.siftcmd import SiFT_CMD, SiFT_CMD_Error
from Crypto.PublicKey import RSA


class Server:
    def __init__(self):
        # ------------------------ CONFIG -----------------------------
        self.server_usersfile = 'users.txt'
        self.server_usersfile_coding = 'utf-8'
        self.server_usersfile_rec_delimiter = '\n'
        self.server_usersfile_fld_delimiter = ':'
        self.server_rootdir = './users/'
        self.server_ip = socket.gethostbyname('localhost')
        #self.server_ip = '192.168.21.206'
        #self.server_ip = socket.gethostbyname(socket.gethostname())
        self.server_port = 5150
        # -------------------------------------------------------------
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.server_ip, self.server_port))
        self.server_socket.listen(5)
        print('Listening on ' + self.server_ip + ':' + str(self.server_port))

        self.accept_connections()

    def load_users(self, usersfile):
        users = {}
        with open(usersfile, 'rb') as f:
            allrecords = f.read().decode(self.server_usersfile_coding)
        records = allrecords.split(self.server_usersfile_rec_delimiter)
        for r in records:
            fields = r.split(self.server_usersfile_fld_delimiter)
            username = fields[0]
            usr_struct = {}
            usr_struct['pwdhash'] = bytes.fromhex(fields[1])
            usr_struct['icount'] = int(fields[2])
            usr_struct['salt'] = bytes.fromhex(fields[3])
            usr_struct['rootdir'] = fields[4]
            users[username] = usr_struct
        return users

    def accept_connections(self):
        while True:
            client_socket, addr = self.server_socket.accept()
            threading.Thread(target=self.handle_client,
                             args=(client_socket, addr, )).start()

    def handle_client(self, client_socket, addr):
        print('New client on ' + addr[0] + ':' + str(addr[1]))

        mtp = SiFT_MTP(client_socket)

        # read in keypair
        # passphrase = getpass.getpass(
        #     'Enter a passphrase to decode the saved private key: ')
        with open("keypair.pem", 'rb') as f:
            keypairstr = f.read()
        try:
            keypair = RSA.import_key(keypairstr)
        except ValueError:
            print('Error: Cannot import private key from file keypair.pem')
            sys.exit(1)

        loginp = SiFT_LOGIN(mtp)
        users = self.load_users(self.server_usersfile)
        loginp.set_server_users(users)

        try:
            user = loginp.handle_login_server(keypair)
        except SiFT_LOGIN_Error as e:
            print('SiFT_LOGIN_Error: ' + e.err_msg)
            print('Closing connection with client on ' +
                  addr[0] + ':' + str(addr[1]))
            client_socket.close()
            return

        cmdp = SiFT_CMD(mtp)
        cmdp.set_server_rootdir(self.server_rootdir)
        cmdp.set_user_rootdir(users[user]['rootdir'])

        while True:
            try:
                cmdp.receive_command()
            except SiFT_CMD_Error as e:
                print('SiFT_CMD_Error: ' + e.err_msg)
                print('Closing connection with client on ' +
                      addr[0] + ':' + str(addr[1]))
                client_socket.close()
                return


# main
if __name__ == '__main__':
    server = Server()
