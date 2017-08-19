# [Software-Security-Learning](https://chybeta.github.io/2017/08/19/Software-Security-Learning/)

在学习软件安全的过程中整合的一些资料。
该repo会不断更新，最近更新日期为：2017/8/19。
同步更新于： [chybeta: Software-Security-Learning ](https://chybeta.github.io/2017/08/19/Software-Security-Learning/) 


---

# Bin Securiy

## Tools

* [Angr：The next-generation binary analysis platform  ](https://github.com/angr/angr)
  * [Angr：一个具有动态符号执行和静态分析的二进制分析工具 ](http://www.freebuf.com/sectool/143056.html)
  * [angr初探](http://bestwing.me/2017/03/08/angr-study/)
* [PEDA - Python Exploit Development Assistance for GDB](https://github.com/longld/peda)
* [pwntools - CTF framework and exploit development library](https://github.com/Gallopsled/pwntools)

## Course

* [Modern Binary
  Exploitation]([http://security.cs.rpi.edu/courses/binexp-spring2015/](http://security.cs.rpi.edu/courses/binexp-spring2015/)\)
* [Linux \(x86\) Exploit Development Series](https://sploitfun.wordpress.com/2015/06/26/linux-x86-exploit-development-tutorial-series/)
* [liveoverflow: Binary Hacking Course](http://liveoverflow.com/binary_hacking/index.html)
* [Lots of  Tutorials](https://www.fuzzysecurity.com/tutorials.html)

### Hack The Virtual Memory

* [Hack The Virtual Memory: C strings & /proc](https://blog.holbertonschool.com/hack-the-virtual-memory-c-strings-proc/)
* [Hack The Virtual Memory: Python bytes](https://blog.holbertonschool.com/hack-the-virtual-memory-python-bytes/)
* [Hack the Virtual Memory: drawing the VM diagram](https://blog.holbertonschool.com/hack-the-virtual-memory-drawing-the-vm-diagram/)
* [Hack the Virtual Memory: malloc, the heap & the program break](https://blog.holbertonschool.com/hack-the-virtual-memory-malloc-the-heap-the-program-break/)

### Exploit writing tutorial

* [Stack Based Overflows](https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/)
* [Stack Based Overflows – jumping to shellcode](https://www.corelan.be/index.php/2009/07/23/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-2/)
* [SEH Based Exploits](https://www.corelan.be/index.php/2009/07/25/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-3-seh/)
* [SEH Based Exploits – just another example](https://www.corelan.be/index.php/2009/07/28/seh-based-exploit-writing-tutorial-continued-just-another-example-part-3b/)
* [From Exploit to Metasploit – The basics](https://www.corelan.be/index.php/2009/08/12/exploit-writing-tutorials-part-4-from-exploit-to-metasploit-the-basics/)
* [How debugger modules & plugins can speed up basic exploit development](https://www.corelan.be/index.php/2009/09/05/exploit-writing-tutorial-part-5-how-debugger-modules-plugins-can-speed-up-basic-exploit-development/)
* [Bypassing Stack Cookies, SafeSeh, SEHOP, HW DEP and ASLR](https://www.corelan.be/index.php/2009/09/21/exploit-writing-tutorial-part-6-bypassing-stack-cookies-safeseh-hw-dep-and-aslr/)
* [Unicode – from 0x00410041 to calc](https://www.corelan.be/index.php/2009/11/06/exploit-writing-tutorial-part-7-unicode-from-0x00410041-to-calc/)
* [Win32 Egg Hunting](https://www.corelan.be/index.php/2010/01/09/exploit-writing-tutorial-part-8-win32-egg-hunting/)
* [Introduction to Win32 shellcoding](https://www.corelan.be/index.php/2010/02/25/exploit-writing-tutorial-part-9-introduction-to-win32-shellcoding/)
* [Chaining DEP with ROP](https://www.corelan.be/index.php/2010/06/16/exploit-writing-tutorial-part-10-chaining-dep-with-rop-the-rubikstm-cube/)
* [Heap Spraying Demystified](https://www.corelan.be/index.php/2011/12/31/exploit-writing-tutorial-part-11-heap-spraying-demystified/)

## 基础知识

* [Linux中的GOT和PLT到底是个啥？ ](http://www.freebuf.com/articles/system/135685.html)
* [关于符号执行](https://github.com/enzet/symbolic-execution)

## ROP

### 一步一步ROP

* [一步一步学ROP之linux\_x86篇](http://cb.drops.wiki/drops/tips-6597.html)
* [一步一步学ROP之linux\_x86篇](http://cb.drops.wiki/drops/papers-7551.html)
* [一步一步学ROP之gadgets和2free篇](http://cb.drops.wiki/drops/binary-10638.html)
* [一步一步学ROP之Android ARM 32位篇](http://cb.drops.wiki/drops/papers-11390.html)

### 基本ROP

* [ropasaurusrex: a primer on return-oriented programming2](https://blog.skullsecurity.org/2013/ropasaurusrex-a-primer-on-return-oriented-programming)
* [ROP技术入门教程](http://bobao.360.cn/learning/detail/3569.html)
* [二进制漏洞利用中的ROP技术研究与实例分析](https://xianzhi.aliyun.com/forum/read/840.html?fpage=2)
* [现代栈溢出利用技术基础：ROP](http://bobao.360.cn/learning/detail/3694.html)
* [通过ELF动态装载构造ROP链](http://blog.neargle.com/SecNewsBak/drops/通过ELF动态装载构造ROP链 （ Return-to-dl-resolve）.html)
* [Swing: 基础栈溢出复习 二 之 ROP ](http://bestwing.me/2017/03/19/stack-overflow-two-ROP/)

### BROP

* [Blind Return Oriented Programming](https://raw.githubusercontent.com/phith0n/Mind-Map/master/渗透测试.png)
* [Swing: 基础栈溢出复习 四 之 BROP ](http://bestwing.me/2017/03/24/stack-overflow-four-BROP/)

### SROP

* [Sigreturn Oriented Programming \(SROP\) Attack攻击原理](http://www.freebuf.com/articles/network/87447.html)
* [Swing: 基础栈溢出复习 三 之 SROP ](http://bestwing.me/2017/03/20/stack-overflow-three-SROP/)

### Return-to-dl-resolve

* [通过ELF动态装载构造ROP链 （ Return-to-dl-resolve）](http://www.evil0x.com/posts/19226.html)

## 栈漏洞

* [手把手教你栈溢出从入门到放弃（上）](http://bobao.360.cn/learning/detail/3717.html)
* [手把手教你栈溢出从入门到放弃（下）](http://bobao.360.cn/learning/detail/3718.html)
* [Hcamael: PWN学习总结之基础栈溢出](http://0x48.pw/2016/11/03/0x26/)
* [Hcamael: PWN学习总结之基础栈溢出2 ](http://0x48.pw/2016/11/21/0x27/)
* [Swing: 基础栈溢出复习 之基础](http://bestwing.me/2017/03/18/stack-overflow-one/)
* [ARM栈溢出攻击实践：从虚拟环境搭建到ROP利用 ](http://www.freebuf.com/articles/terminal/107276.html)
* [64-bit Linux stack smashing tutorial: Part 1](https://blog.techorganic.com/2015/04/10/64-bit-linux-stack-smashing-tutorial-part-1/)
* [64-bit Linux stack smashing tutorial: Part 2](https://blog.techorganic.com/2015/04/21/64-bit-linux-stack-smashing-tutorial-part-2/)
* [64-bit Linux stack smashing tutorial: Part 3](https://blog.techorganic.com/2016/03/18/64-bit-linux-stack-smashing-tutorial-part-3/)
* [Offset2lib: bypassing full ASLR on 64bit Linu](http://cybersecurity.upv.es/attacks/offset2lib/offset2lib.html)

## 堆漏洞

* [Heap Exploitation](https://heap-exploitation.dhavalkapil.com/introduction.html)
* [how2heap](https://github.com/shellphish/)

### 堆相关知识

* [PWN之堆内存管理](http://paper.seebug.org/255/)
* [Linux堆内存管理深入分析（上） ](http://www.freebuf.com/articles/system/104144.html)
* [Linux堆内存管理深入分析（下） ](http://www.freebuf.com/articles/security-management/105285.html)
* [Windows Exploit开发系列教程——堆喷射（一）](http://bobao.360.cn/learning/detail/3548.html)
* [Windows Exploit开发系列教程——堆喷射（二）](http://bobao.360.cn/learning/detail/3555.html)
* [Libc堆管理机制及漏洞利用技术 \(一） ](http://www.freebuf.com/articles/system/91527.html)
* [Notes About Heap Overflow Under Linux](https://blog.iret.xyz/article.aspx/linux_heapoverflow_enterance)
* [如何理解堆和堆溢出漏洞的利用?](http://www.freebuf.com/vuls/98404.html)

### 堆利用技术

* [现代化的堆相关漏洞利用技巧](http://bobao.360.cn/learning/detail/3197.html)
* [从一字节溢出到任意代码执行-Linux下堆漏洞利用](http://bobao.360.cn/learning/detail/3113.html)
* [Heap overflow using unlink](https://sploitfun.wordpress.com/2015/02/26/heap-overflow-using-unlink/?spm=a313e.7916648.0.0.x4nzYZ)
* [Linux堆溢出漏洞利用之unlink](https://jaq.alibaba.com/community/art/show?spm=a313e.7916646.24000001.74.ZP8rXN&articleid=360)
* [Linux堆溢出之Fastbin Attack实例详解](http://bobao.360.cn/learning/detail/3996.html)
* [unsorted bin attack分析](http://bobao.360.cn/learning/detail/3296.html)
* [Double Free浅析](http://www.vuln.cn/6172)
* \[Understanding the heap by
  breaking it\]\([http://www.blackhat.com/presentations/bh-usa-07/Ferguson/Whitepaper/bh-usa-07-ferguson-WP.pdf](http://www.blackhat.com/presentations/bh-usa-07/Ferguson/Whitepaper/bh-usa-07-ferguson-WP.pdf)\)
* [An Introduction to Use After Free Vulnerabilities](https://www.purehacking.com/blog/lloyd-simon/an-introduction-to-use-after-free-vulnerabilities)
* [Use After Free漏洞浅析](http://bobao.360.cn/learning/detail/3379.html?utm_source=tuicool&utm_medium=referral)
* [Linux堆漏洞之Use after free实例](http://d0m021ng.github.io/2017/03/04/PWN/Linux堆漏洞之Use-after-free实例/)
* [堆之House of Spirit](http://bobao.360.cn/learning/detail/3417.html)

## 格式化字符串漏洞

* [二进制漏洞之——邪恶的printf](http://cb.drops.wiki/drops/binary-6259.html)
* [漏洞挖掘基础之格式化字符串](http://cb.drops.wiki/drops/papers-9426.html)
* [格式化字符串漏洞利用小结（一）](http://bobao.360.cn/learning/detail/3654.html)
* [格式化字符串漏洞利用小结（二）](http://bobao.360.cn/learning/detail/3674.html)
* [Linux下的格式化字符串漏洞利用姿势](http://www.cnblogs.com/Ox9A82/p/5429099.html)
* [Exploiting Format String Vulnerabilities](https://crypto.stanford.edu/cs155/papers/formatstring-1.2.pdf)

## 其余漏洞

### FSP溢出

* [Head First FILE Stream Pointer Overflow](http://blog.neargle.com/SecNewsBak/drops/Head First FILE Stream Pointer Overflow.html)
* [abusing the FILE structure](https://outflux.net/blog/archives/2011/12/22/abusing-the-file-structure/)
* [File Stream Pointer Overflows Paper.](https://outflux.net/blog/archives/2011/12/22/abusing-the-file-structure/)
* [溢出利用FILE结构体](http://bobao.360.cn/learning/detail/3219.html)

### 整数溢出

* [整数溢出漏洞](http://blog.csdn.net/wuxiaobingandbob/article/details/44618925)

## 保护绕过

### Cannary绕过

* [栈溢出之绕过CANARY保护 ](http://0x48.pw/2017/03/14/0x2d/)
* [论canary的几种玩法](http://veritas501.space/2017/04/28/论canary的几种玩法/)
* [Liunx下关于绕过cancry保护总结](http://yunnigu.dropsec.xyz/2017/03/20/Liunx下关于绕过cancry保护总结/)

## 内核

* \[HackSysExtremeVulnerableDriver
  \]\([https://github.com/hacksysteam/HackSysExtremeVulnerableDriver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver)\)
* [Starting with Windows Kernel Exploitation – part 1 – setting up the lab](https://hshrzd.wordpress.com/2017/05/28/starting-with-windows-kernel-exploitation-part-1-setting-up-the-lab/)
* [Starting with Windows Kernel Exploitation – part 2 – getting familiar with HackSys Extreme Vulnerable Driver](https://hshrzd.wordpress.com/2017/06/05/starting-with-windows-kernel-exploitation-part-2/)
* [Windows内核利用之旅：熟悉HEVD（附视频演示）](http://bobao.360.cn/learning/detail/4002.html)
* [Windows 内核攻击：栈溢出](bobao.360.cn/learning/detail/3718.html)
* [Linux 内核漏洞利用教程（一）：环境配置](http://bobao.360.cn/learning/detail/3700.html)
* [Linux 内核漏洞利用教程（二）：两个Demo](http://bobao.360.cn/learning/detail/3702.html)
* [Linux 内核漏洞利用教程（三）：实践 CSAW CTF 题目](http://bobao.360.cn/learning/detail/3706.html)
* [Linux内核ROP姿势详解\(一\) ](http://www.freebuf.com/articles/system/94198.html)
* [Linux内核ROP姿势详解（二）](http://www.freebuf.com/articles/system/135402.html)

## 虚拟机逃逸

* [虚拟机逃逸——QEMU的案例分析（一）](http://bbs.pediy.com/thread-217997.htm)
* [虚拟机逃逸——QEMU的案例分析（二）](http://bbs.pediy.com/thread-217999.htm)
* [虚拟机逃逸——QEMU的案例分析（三） ](http://bbs.pediy.com/thread-218045.htm)

## ARM

* [ARM 汇编基础速成1：ARM汇编以及汇编语言基础介绍](http://bobao.360.cn/learning/detail/4070.html)
* [ARM 汇编基础速成2：ARM汇编中的数据类型](http://bobao.360.cn/learning/detail/4075.html)
* [ARM 汇编基础速成3：ARM模式与THUMB模式](http://bobao.360.cn/learning/detail/4082.html)
* [ARM 汇编基础速成4：ARM汇编内存访问相关指令](http://bobao.360.cn/learning/detail/4087.html)
* [ARM 汇编基础速成5：连续存取](http://bobao.360.cn/learning/detail/4097.html)
* [ARM 汇编基础速成6：条件执行与分支](http://bobao.360.cn/learning/detail/4104.html)
* [ARM 汇编基础速成7：栈与函数](http://bobao.360.cn/learning/detail/4108.html)

## 进程注入

* [10种常见的进程注入技术的总结](http://bobao.360.cn/learning/detail/4131.html)
* [系统安全攻防战：DLL注入技术详解 ](http://www.freebuf.com/articles/system/143640.html)

## CTF中的pwn

* [pwn & exploit](https://github.com/jmpews/pwn2exploit)

### 入门

* [跟我入坑PWN第一章](http://bobao.360.cn/learning/detail/3300.html)
* [跟我入坑PWN第二章](http://bobao.360.cn/learning/detail/3339.html)

### 技巧

* [借助DynELF实现无libc的漏洞利用小结](http://bobao.360.cn/learning/detail/3298.html?utm_source=tuicool&utm_medium=referral)

### 总结

* [CTF总结](https://github.com/stfpeak/CTF)
* [pwn tips](http://skysider.com/?p=223)
* [CTF-pwn-tips](https://github.com/Naetw/CTF-pwn-tips)
* [pwn 学习总结](http://www.angelwhu.com/blog/?p=460)
* [CTF中做Linux下漏洞利用的一些心得](http://www.cnblogs.com/Ox9A82/p/5559167.html)
* [linux常见漏洞利用技术实践](http://drops.xmd5.com/static/drops/binary-6521.html)

### WP

* [一道有趣的CTF PWN题](http://bobao.360.cn/learning/detail/3189.html)
* [Exploit-Exercises Nebula全攻略](https://github.com/1u4nx/Exploit-Exercises-Nebula)
* [三个白帽之从pwn me调试到Linux攻防学习](http://blog.neargle.com/SecNewsBak/drops/三个白帽之从pwn me调试到Linux攻防学习.html)

# 安卓安全

* [Android安全项目入门篇](https://mp.weixin.qq.com/s?__biz=MzI4NjEyMDk0MA==&mid=2649846643&idx=1&sn=0286e8f1b3e6da0acbd129cb248eac2a)



