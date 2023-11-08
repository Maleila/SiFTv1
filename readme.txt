To-do list:

For client.py and server.py files:
1. Generate an RSA key-pair 
	- put the key-pair file in the server folder 
	- put the public key file in the client folder

** Created a RSA key-pair that has to be generated manually and put into the sever and client files manually

2. Modify server.py and client.py to read these keys and use them for session key establishment.

For mtp.py and login.py files:
3. Modify both the server and client code to incorporate the RSA keys
	- Extend the login protocol
		- with session key establishment (key exchange and key derivation)

	- Extend the message transfer protocol
		- with cryptographic functions and replay protection



-------------------------------------------------

Input username and password 
 -> compute pwdhash
  -> compare pwdhash to pwdhash stored in server
   -> make sure pwdhash of the correct username 