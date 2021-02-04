# shellcode

开启沙箱考察orw的编写，利用shellcraft很容易

## shellcode 中jmp的利用

jmp的跳转范围（段内机器码\xe9）：

+   jmp short 标号(IP的修改范围为-128至127)

+   jmp near ptr 标号(IP的修改范围为-32768至32767)

可以理解为：

+   jmp signed char
+   jmp signed int
+   jmp signed long

后面的有符号数就是段内偏移