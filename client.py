import sys
import math
import time
import utils
import base64
import random
import socket
import pickle
from utils import mapping
from utils import Header, Message

HOST = '127.0.0.1'
PORT = 17084

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def connect():
	global s
	s.connect((HOST, PORT))

def exit(msg):
	global s
	print msg
	s.close()
	sys.exit()

def start(q, alpha, xa, ya):
	global s

	found = False

	s.send('start')

	data = s.recv(1024).decode()

	if data == 'ok':
		data = s.recv(1024).decode()
		if data:
			yb = int(data)
			s.send(str(ya))
			k = int(utils.mod_pow(yb, xa, q))
			found = True
			return k
		else:
			print 'Some error occurred'
			s.close()
			sys.exit()
	return -1

def get_q():
	return 97

def get_alpha(q):
	return 87

def get_xa():
	return random.randint(1, 8273)

def get_qa():
	return 97

def dh():
	q = get_q()
	alpha = get_alpha(q)
	xa = get_xa()
	ya = int(utils.mod_pow(alpha, xa, q))
	return q, alpha, xa, ya

def decrypt(filename, k):
	file = open(filename + '.enc', 'r')
	out = open(filename + '.dec', 'w')
	length = len(mapping)
	for line in file:
		for char in line:
			pos = (mapping.index(char) - k) % length
			out.write(mapping[pos])
	file.close()
	out.close()

def login_create(k):
	global s

	userid = raw_input("Enter ID: ")
	password = raw_input("Enter Password: ")

	if len(password) > 8:
		print "Password Length greater than 8"
		return False

	qa = get_qa()
	cmd = 'LOGINCREATE'
	opcode = 10

	message = getMessage("", opcode, cmd, utils.enc(str(userid), k), utils.enc(str(password), k), utils.enc(str(qa), k))
	msg = pickle.dumps(message)

	s.send(msg)

	data = s.recv(1024)

	if not data:
		exit('Data receive error')

	resp = pickle.loads(data)

	if resp.status == 'SUCCESSFUL':
		return True

	return False

def auth_request(k):
	global s

	userid = raw_input("Enter ID: ")
	password = raw_input("Enter Password: ")

	if len(password) > 8:
		print "Password Length greater than 8"
		return False

	cmd = 'AUTHREQUEST'
	opcode = 30

	message = getMessage("", opcode, cmd, utils.enc(str(userid), k), utils.enc(str(password), k), "")
	msg = pickle.dumps(message)

	s.send(msg)

	data = s.recv(1024)

	if not data:
		exit('Data receive error')

	resp = pickle.loads(data)

	if resp.status == 'SUCCESSFUL':
		return True

	return False

def service_request(k):
	global s

	filename = raw_input("Enter filename: ")

	cmd = 'SERVICEREQUEST'
	opcode = 50

	message = getMessage(filename, opcode, cmd, "", "", "")
	msg = pickle.dumps(message)
	s.send(msg)

	with open('output.txt', 'w') as f:
		while True:
			data = s.recv(1024)

			if data.strip()[-4:] == 'done':
				f.write(data[:-4])
				break

			f.write(data)

def getMessage(buf, opcode, cmd, userid, password, qa, status=""):
	header = Header(opcode, cmd)
	message = Message(header, buf, userid, password, qa, status)
	return message

if __name__ == '__main__':
	print 'Initializing'
	connect()
	print 'Establishing DH Key'
	q, alpha, xa, ya = dh()
	k = start(q, alpha, xa, ya)
	if k == -1:
		exit('DH Key Error')
	print 'DH Key Established Successfully'

	pos = 0

	while pos != 3:
		print '1. Register to Server (LOGINCREATE)'
		print '2. Login to Server (LOGINAUTH)'
		print '3. Exit'
		pos = int(raw_input('Enter choice: '))
		if pos < 1 or pos > 3:
			print 'Invalid choice'
		if pos == 1:
			ch = 0
			if login_create(k):
				while ch != 2:
					print '1. Retreive File (SERVICEREQUEST)'
					print '2. Back'
					ch = int(raw_input('Enter choice: '))
					if ch < 1 or ch > 2:
						print 'Invalid choice'
					if ch == 1:
						service_request(k)
			else:
				print 'User already exists!'
		if pos == 2:
			ch = 0
			if auth_request(k):
				while ch != 2:
					print '1. Retreive File (SERVICEREQUEST)'
					print '2. Back'
					ch = int(raw_input('Enter choice: '))
					if ch < 1 or ch > 2:
						print 'Invalid choice'
					if ch == 1:
						service_request(k)
			else:
				print 'Incorrect ID or Password'

	exit('Everything Good\nExiting')
