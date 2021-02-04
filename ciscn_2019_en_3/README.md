# UAF_In_Tcache

2.27环境下存在UAF漏洞，且前面一部分可以利用puts泄露libc地址

然后tcache attack向free中填入system。

onegadget全部失效，realloc调整也失效