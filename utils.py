import math
import random

mapping = [' ', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', ',', '.', '?', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '!', '\n']

class Header:
    def __init__(self, opcode, cmd):
        self.opcode = opcode 
        self.cmd = cmd

class Message:
    def __init__(self, header, buf, userid, password, qa, status=""):
        self.header = header 
        self.buf = buf 
        self.userid = userid 
        self.password = password 
        self.qa = qa 
        self.status = status

def mod_pow(num, exp, mod):
	res = 1
	num = num % mod

	while exp > 0:
		if exp%2:
			res = (res*num)%mod
		exp >>= 1
		num = math.pow(num, 2) % mod

	return res

def enc(input, k):
	output = ''
	length = len(mapping)
	for char in input:
		pos = (mapping.index(char) + k) % length
		output += mapping[pos]
	return output

def dec(input, k):
	output = ''
	length = len(mapping)
	for char in input:
		pos = (mapping.index(char) - k) % length
		output += mapping[pos]
	return output