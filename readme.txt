To-do list:

For client.py and server.py files:
1. Generate an RSA key-pair 
	- put the key-pair file in the server folder 
	- put the public key file in the client folder

2. Modify server.py and client.py to read these keys and use them for session key establishment.

For mtp.py and login.py files:
3. Modify both the server and client code to incorporate the RSA keys
	- Extend the login protocol
		- with session key establishment (key exchange and key derivation)

	- Extend the message transfer protocol
		- with cryptographic functions and replay protection


Lengths:
msg_header: 16 bytes (the same for login request and login response)
	len: 2 bytes
	sqn: 2 bytes
	rnd: 6 bytes
	rsv: 2 bytes
	ver: 
	typ:

mac: 12 bytes (! currently 16)

payload: 12 bytes
	login request:
		client_random (r): 16 bytes
		username: string
		password: string
		timestamp: unsigned integer
	login response:
		server_random (r): 16 bytes
		request_hash: SHA-256 hash of the payload converted to bytes

TK: 32 bytes AES key

etk: 265 bytes






-------------------------------------------------

Input username and password 
 -> compute pwdhash
  -> compare pwdhash to pwdhash stored in server
   -> make sure pwdhash of the correct username 



Logic Order:

- Send a login request from client to server (header, epd, mac, etk)
- In server:
	-> decrypt etk with private RSA keypair
	-> verify mac
	-> use decrypted tk to decrypt epd
	-> verify login credentials
	-> if everything checks out, send login response to client (header + epd + mac) 
		and adopt final transer key
	
- In client:
	-> verify mac
	-> decrypt epd witth temporary key
	-> verify request hash
	-> if everything checks out, set current key to final transer key and discard TK
