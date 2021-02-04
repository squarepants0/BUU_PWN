# UAF

题目主要利用点是UAF漏洞

利用fastbin attack获取bss段上的chunk，控制ptr指针，这样就可进行任意地址读写

## 脚本编写

程序开头的输入code结合选项1的fmtstr可以泄楼elf加载地址，不过由于格式化字符串不是对齐的所以需要多次调整泄露点，且需进行过滤

