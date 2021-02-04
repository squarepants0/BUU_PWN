#+++++++++++++++++++exp.py++++++++++++++++++++
#!/usr/bin/python
# -*- coding:utf-8 -*-                           
#Author: Square_R
#Time: 2021.01.28 16.58.56
#+++++++++++++++++++exp.py++++++++++++++++++++
from pwn import*

context.arch = 'amd64'

def add(size,cont):
	sh.sendlineafter('Choice: ','')
	sh.sendlineafter('Size: ',str(size))
	sh.sendlineafter('Content: ',str(cont))

def edit(index,cont):
	sh.sendlineafter('Choice: ','')
	sh.sendlineafter('Index: ',str(index))
	sh.sendlineafter('Content: ',str(cont))

def delete(index):
	sh.sendlineafter('Choice: ','')
	sh.sendlineafter('Index: ',str(index))

def show(index):
	sh.sendlineafter('Choice: ','')
	sh.sendlineafter('Index: ',str(index))

def show_addr(name,addr):
	log.success('The '+str(name)+' Addr:' + str(hex(addr)))


host = '1.1.1.1'
port = 10000
local = 1
if local:
	context.log_level = 'debug'
	libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
	sh = process('./axb_2019_heap')
else:
	#context.log_level = 'debug'
	libc=ELF('./libc-2.23_x64_1604.so')
	sh = remote(host,port)



def pwn():




if __name__ == '__main__':
	pwn()
	sh.interactive()

