import csv
import sys
import math
import time
import utils
import base64
import random
import socket
import pickle
import os.path
import hashlib
import threading
from utils import mapping
from utils import Header
from utils import Message

HOST = '127.0.0.1'
PORT = 17084

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn = None
addr = None

fields = ['id', 'salt', 'password', 'prime']

def init():
	filename = 'password.csv'
	with open(filename, 'w') as csvfile:
		writer = csv.DictWriter(csvfile, fieldnames = fields)
		writer.writeheader()
		writer.writerow({'id' : '1', 'salt': 1234, 'password': 'aaaa', 'prime': 97})
		writer.writerow({'id' : '2', 'salt': 1234, 'password': 'bbbb', 'prime': 97})
		writer.writerow({'id' : '3', 'salt': 1234, 'password': 'cccc', 'prime': 97})
		writer.writerow({'id' : '4', 'salt': 1234, 'password': 'dddd', 'prime': 97})	

def exit(msg):
	global s
	print msg
	s.close()
	sys.exit()

def start(q, alpha, xb, yb):
	global s, conn, addr

	print "Connected by ", addr
	start = False
	found = False
	k = 0

	while not found:
		if not start:
			data = conn.recv(1024).decode()

		if not data:
			print 'Data not received\nExiting...'
			s.close()
			sys.exit()

		if start:
			ya = 0
			conn.send(str(yb))
			data = conn.recv(1024).decode()
			if data:
				ya = int(data.strip())
				k = int(utils.mod_pow(ya, xb, q))
				found = True
				start = False
			else:
				print 'Some error occurred'
				s.close()
				sys.exit()

		if data.strip() == 'start':
			conn.send('ok')
			start = True

	if not found:
		return -1
	return k

def get_q():
	return 97

def get_alpha(q):
	return 87

def get_xb():
	return random.randint(1, 8273)

def get_salt():
	return random.randint(1, 8273)

def dh():
	q = get_q()
	alpha = get_alpha(q)
	xb = get_xb()
	yb = int(utils.mod_pow(alpha, xb, q))
	return q, alpha, xb, yb

def encrypt(filename, k):
	file = open(filename, 'r')
	out = open(filename + '.enc', 'w')
	length = len(mapping)
	for line in file:
		for char in line:
			pos = (mapping.index(char) + k) % length
			out.write(mapping[pos])
	file.close()
	out.close()

def isUser(userid):
	with open('password.csv') as csvFile:
		csvReader = csv.reader(csvFile, delimiter=',')
		for row in csvReader:
			if row[0] == userid:
				return True
	return False

def checkCreds(userid, password):
	with open('password.csv') as csvFile:
		csvReader = csv.reader(csvFile, delimiter=',')
		for row in csvReader:
			hashPassword = hashlib.sha1(str(password) + str(row[1]) + str(row[3])).digest()
			if row[0] == userid and row[2] == hashPassword:
				return True
	return False


def getMessage(buf, opcode, cmd, userid, password, qa, status=""):
	header = Header(opcode, cmd)
	message = Message(header, buf, userid, password, qa, status)
	return message

def writeUser(userid, password, qa):
	with open('password.csv', 'a') as csvFile:
		writer = csv.DictWriter(csvFile, fieldnames = fields)
		salt = get_salt()
		hashPassword = hashlib.sha1(str(password) + str(salt) + str(qa)).digest()
		# print 'Hashed Password: ', hashPassword
		writer.writerow({'id' : str(userid), 'salt': str(salt), 'password': hashPassword, 'prime': str(qa)})

def login_create(data, k):

	req = pickle.loads(data)

	userid = utils.dec(req.userid, k)
	password = utils.dec(req.password, k)
	qa = utils.dec(req.qa, k)

	print 'User ID: ', userid
	print 'Password: ', password
	print 'QA: ', qa

	status = 'SUCCESSFUL'

	if isUser(userid):
		status = 'UNSUCCESSFUL'
	else:
		writeUser(userid, password, qa)

	return status

def auth_request(data, k):

	req = pickle.loads(data)

	userid = utils.dec(req.userid, k)
	password = utils.dec(req.password, k)
	qa = utils.dec(req.qa, k)

	print 'User ID: ', userid
	print 'Password: ', password
	print 'QA: ', qa

	status = 'SUCCESSFUL'

	if not checkCreds(userid, password):
		status = 'UNSUCCESSFUL'

	return status

def service_request(data, k):
	global conn

	req = pickle.loads(data)

	filename = req.buf

	print 'File Requested: ', filename

	f = open(filename, 'r')
	l = f.read(1024)

	while l:
		conn.send(l)
		l = f.read(1024)
	f.close()
	conn.send('done')

	# global conn

	# req = pickle.loads(data)

	# filename = req.buf

	# print 'File Requested: ', filename

	# f = open(filename, 'r')
	# l = f.read(1024)

	# while l:
	# 	message = getMessage(utils.enc(l, k), "", "", "", "", "", "")
	# 	msg = pickle.dumps(message)
	# 	conn.send(msg)
	# 	l = f.read(1024)
	# f.close()
	# message = getMessage(utils.enc('done', k), "", "", "", "", "", "")
	# msg = pickle.dumps(message)
	# conn.send(msg)

def serve(conn, k):
	while True:
		data = conn.recv(1024)

		if not data:
			continue
			# exit('Data receive error')

		req = pickle.loads(data)

		if req.header.opcode == 10:
			status = login_create(data, k)
			print 'CMD: ', req.header.cmd, 'STATUS: ', status
			message = getMessage("", 20, 'LOGINREPLY', "", "", "", status)
			msg = pickle.dumps(message)
			conn.send(msg)

		if req.header.opcode == 30:
			status = auth_request(data, k)
			print 'CMD: ', req.header.cmd, 'STATUS: ', status
			message = getMessage("", 40, 'AUTHREPLY', "", "", "", status)
			msg = pickle.dumps(message)
			conn.send(msg)

		if req.header.opcode == 50:
			service_request(data, k)

	exit('Everything Good\nExiting')


if __name__ == '__main__':
	print 'Initializing...'
	s.bind((HOST, PORT))
	s.listen(100)
	while True:
		conn, addr = s.accept()
		print 'Establishing DH Key'
		q, alpha, xb, yb = dh()
		k = start(q, alpha, xb, yb)
		if k == -1:
			exit('DH Key error')
		print 'DH Key Established Successfully'
		t1 = threading.Thread(target=serve, args=(conn, k))
		t1.start()

	