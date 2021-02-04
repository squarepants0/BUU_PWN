# 关键漏洞

在call函数中进行free name_chunk时指针未置零造成UAF。

## 思路

环境为2.27存在tcache所以利用tcache attack将libc地址泄露

然后再次tcache attack将free_hook写入system地址或者向malloc_hook写入onegadget，这里我使用第一种方法。第二种方法的onedaget都失效