# [Software-Security-Learning](https://chybeta.github.io/2017/08/19/Software-Security-Learning/)

在学习Software安全的过程中整合的一些资料。
该repo会不断更新，最近更新日期为：2017/10/04。

同步更新于： [chybeta: Software-Security-Learning (带目录) ](https://chybeta.github.io/2017/08/19/Software-Security-Learning/) 

10月06日更新小记：
+ 新收录文章：
	+ ROP	
		+ [如何在32位系统中使用ROP+Return-to-dl来绕过ASLR+DEP](http://www.freebuf.com/articles/system/149214.html)
	+ 浏览器安全
		+ [IE漏洞攻防编年简史](http://blog.topsec.com.cn/ad_lab/ie%E6%BC%8F%E6%B4%9E%E6%94%BB%E9%98%B2%E7%BC%96%E5%B9%B4%E7%AE%80%E5%8F%B2/)
		+ [IE浏览器漏洞综合利用技术：UAF利用技术的发展](http://bobao.360.cn/learning/detail/3666.html)
		+ [IE浏览器漏洞综合利用技术：堆喷射技术](http://bobao.360.cn/learning/detail/3656.html)
		+ [cure53-browser-sec-whitepaper](https://github.com/cure53/browser-sec-whitepaper)
		+ [X41-Browser-Security-White-Paper.pdf](https://browser-security.x41-dsec.de/X41-Browser-Security-White-Paper.pdf)
<!-- more -->
	
---

# Bin Securiy
+ [软件安全工程师技能表](https://github.com/feicong/sec_skills)

## Tools
+ [pharos: Automated static analysis tools for binary programs](https://github.com/cmu-sei/pharos)
+ [Angr：The next-generation binary analysis platform ](https://github.com/angr/angr)
+ [Angr：一个具有动态符号执行和静态分析的二进制分析工具 ](http://www.freebuf.com/sectool/143056.html)
+ [angr初探](http://bestwing.me/2017/03/08/angr-study/)
+ [Vuzzer自动漏洞挖掘工具简单分析附使用介绍](http://www.freebuf.com/sectool/143123.html)
+ [PEDA - Python Exploit Development Assistance for GDB](https://github.com/longld/peda)
+ [pwntools - CTF framework and exploit development library](https://github.com/Gallopsled/pwntools)


## Course

+ [Modern Binary Exploitation](http://security.cs.rpi.edu/courses/binexp-spring2015/)
+ [Linux \(x86\) Exploit Development Series](https://sploitfun.wordpress.com/2015/06/26/linux-x86-exploit-development-tutorial-series/)
+ [liveoverflow: Binary Hacking Course](http://liveoverflow.com/binary_hacking/index.html)
+ [Lots of Tutorials](https://www.fuzzysecurity.com/tutorials.html)

### Hack The Virtual Memory

+ [Hack The Virtual Memory: C strings & /proc](https://blog.holbertonschool.com/hack-the-virtual-memory-c-strings-proc/)
+ [Hack The Virtual Memory: Python bytes](https://blog.holbertonschool.com/hack-the-virtual-memory-python-bytes/)
+ [Hack the Virtual Memory: drawing the VM diagram](https://blog.holbertonschool.com/hack-the-virtual-memory-drawing-the-vm-diagram/)
+ [Hack the Virtual Memory: malloc, the heap & the program break](https://blog.holbertonschool.com/hack-the-virtual-memory-malloc-the-heap-the-program-break/)

### Exploit writing tutorial

+ [Stack Based Overflows](https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/)
+ [Stack Based Overflows – jumping to shellcode](https://www.corelan.be/index.php/2009/07/23/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-2/)
+ [SEH Based Exploits](https://www.corelan.be/index.php/2009/07/25/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-3-seh/)
+ [SEH Based Exploits – just another example](https://www.corelan.be/index.php/2009/07/28/seh-based-exploit-writing-tutorial-continued-just-another-example-part-3b/)
+ [From Exploit to Metasploit – The basics](https://www.corelan.be/index.php/2009/08/12/exploit-writing-tutorials-part-4-from-exploit-to-metasploit-the-basics/)
+ [How debugger modules & plugins can speed up basic exploit development](https://www.corelan.be/index.php/2009/09/05/exploit-writing-tutorial-part-5-how-debugger-modules-plugins-can-speed-up-basic-exploit-development/)
+ [Bypassing Stack Cookies, SafeSeh, SEHOP, HW DEP and ASLR](https://www.corelan.be/index.php/2009/09/21/exploit-writing-tutorial-part-6-bypassing-stack-cookies-safeseh-hw-dep-and-aslr/)
+ [Unicode – from 0x00410041 to calc](https://www.corelan.be/index.php/2009/11/06/exploit-writing-tutorial-part-7-unicode-from-0x00410041-to-calc/)
+ [Win32 Egg Hunting](https://www.corelan.be/index.php/2010/01/09/exploit-writing-tutorial-part-8-win32-egg-hunting/)
+ [Introduction to Win32 shellcoding](https://www.corelan.be/index.php/2010/02/25/exploit-writing-tutorial-part-9-introduction-to-win32-shellcoding/)
+ [Chaining DEP with ROP](https://www.corelan.be/index.php/2010/06/16/exploit-writing-tutorial-part-10-chaining-dep-with-rop-the-rubikstm-cube/)
+ [Heap Spraying Demystified](https://www.corelan.be/index.php/2011/12/31/exploit-writing-tutorial-part-11-heap-spraying-demystified/)

## 基础知识

+ [Linux中的GOT和PLT到底是个啥？ ](http://www.freebuf.com/articles/system/135685.html)
+ [关于符号执行](https://github.com/enzet/symbolic-execution)
+ [教练！那根本不是IO！——从printf源码看libc的IO](http://bobao.360.cn/learning/detail/4490.html)

## ROP

### 一步一步ROP

+ [一步一步学ROP之linux\_x86篇](http://cb.drops.wiki/drops/tips-6597.html)
+ [一步一步学ROP之linux\_x86篇](http://cb.drops.wiki/drops/papers-7551.html)
+ [一步一步学ROP之gadgets和2free篇](http://cb.drops.wiki/drops/binary-10638.html)
+ [一步一步学ROP之Android ARM 32位篇](http://cb.drops.wiki/drops/papers-11390.html)

### 基本ROP
+ [Intro to ROP: ROP Emporium — Split](https://medium.com/@iseethieves/intro-to-rop-rop-emporium-split-9b2ec6d4db08)
+ [ROP Emporium](https://ropemporium.com/)
+ [ropasaurusrex: a primer on return-oriented programming2](https://blog.skullsecurity.org/2013/ropasaurusrex-a-primer-on-return-oriented-programming)
+ [ROP技术入门教程](http://bobao.360.cn/learning/detail/3569.html)
+ [二进制漏洞利用中的ROP技术研究与实例分析](https://xianzhi.aliyun.com/forum/read/840.html?fpage=2)
+ [现代栈溢出利用技术基础：ROP](http://bobao.360.cn/learning/detail/3694.html)
+ [通过ELF动态装载构造ROP链](http://wooyun.jozxing.cc/static/drops/binary-14360.html)
+ [Swing: 基础栈溢出复习 二 之 ROP ](http://bestwing.me/2017/03/19/stack-overflow-two-ROP/)

### BROP

+ [Blind Return Oriented Programming](http://www.scs.stanford.edu/brop/)
+ [muhe: Have fun with Blind ROP](http://o0xmuhe.me/2017/01/22/Have-fun-with-Blind-ROP/)
+ [Swing: 基础栈溢出复习 四 之 BROP ](http://bestwing.me/2017/03/24/stack-overflow-four-BROP/)

### SROP

+ [Sigreturn Oriented Programming \(SROP\) Attack攻击原理](http://www.freebuf.com/articles/network/87447.html)
+ [Swing: 基础栈溢出复习 三 之 SROP ](http://bestwing.me/2017/03/20/stack-overflow-three-SROP/)

### Return-to-dl-resolve

+ [通过ELF动态装载构造ROP链 （ Return-to-dl-resolve）](http://www.evil0x.com/posts/19226.html)

## 栈漏洞

+ [手把手教你栈溢出从入门到放弃（上）](http://bobao.360.cn/learning/detail/3717.html)
+ [手把手教你栈溢出从入门到放弃（下）](http://bobao.360.cn/learning/detail/3718.html)
+ [Hcamael: PWN学习总结之基础栈溢出](http://0x48.pw/2016/11/03/0x26/)
+ [Hcamael: PWN学习总结之基础栈溢出2 ](http://0x48.pw/2016/11/21/0x27/)
+ [Swing: 基础栈溢出复习 之基础](http://bestwing.me/2017/03/18/stack-overflow-one/)
+ [ARM栈溢出攻击实践：从虚拟环境搭建到ROP利用 ](http://www.freebuf.com/articles/terminal/107276.html)
+ [64-bit Linux stack smashing tutorial: Part 1](https://blog.techorganic.com/2015/04/10/64-bit-linux-stack-smashing-tutorial-part-1/)
+ [64-bit Linux stack smashing tutorial: Part 2](https://blog.techorganic.com/2015/04/21/64-bit-linux-stack-smashing-tutorial-part-2/)
+ [64-bit Linux stack smashing tutorial: Part 3](https://blog.techorganic.com/2016/03/18/64-bit-linux-stack-smashing-tutorial-part-3/)
+ [Offset2lib: bypassing full ASLR on 64bit Linu](http://cybersecurity.upv.es/attacks/offset2lib/offset2lib.html)

## 堆漏洞

+ [Heap Exploitation](https://heap-exploitation.dhavalkapil.com/introduction.html)
+ [how2heap](https://github.com/shellphish/)

### 堆相关知识

+ [PWN之堆内存管理](http://paper.seebug.org/255/)
+ [Linux堆内存管理深入分析（上） ](http://www.freebuf.com/articles/system/104144.html)
+ [Linux堆内存管理深入分析（下） ](http://www.freebuf.com/articles/security-management/105285.html)
+ [Windows Exploit开发系列教程——堆喷射（一）](http://bobao.360.cn/learning/detail/3548.html)
+ [Windows Exploit开发系列教程——堆喷射（二）](http://bobao.360.cn/learning/detail/3555.html)
+ [Libc堆管理机制及漏洞利用技术 \(一） ](http://www.freebuf.com/articles/system/91527.html)
+ [Notes About Heap Overflow Under Linux](https://blog.iret.xyz/article.aspx/linux_heapoverflow_enterance)
+ [如何理解堆和堆溢出漏洞的利用?](http://www.freebuf.com/vuls/98404.html)
+ [Have fun with glibc内存管理](http://o0xmuhe.me/2016/11/21/Have-fun-with-glibc%E5%86%85%E5%AD%98%E7%AE%A1%E7%90%86/)
+ [内存映射mmap](http://www.tuicool.com/articles/A7n2ueq)
+ [glibc malloc学习笔记之fastbin](http://0x48.pw/2017/07/25/0x35/)
+ [malloc.c源码阅读之__libc_free](http://0x48.pw/2017/08/07/0x37/)

### 堆利用技术
+ [how2heap总结-上](http://bobao.360.cn/learning/detail/4386.html)
+ [how2heap总结-下](http://bobao.360.cn/learning/detail/4383.html)
+ [溢出科普：heap overflow&溢出保护和绕过](http://wooyun.jozxing.cc/static/drops/binary-14596.html)
+ [现代化的堆相关漏洞利用技巧](http://bobao.360.cn/learning/detail/3197.html)
+ [从一字节溢出到任意代码执行-Linux下堆漏洞利用](http://bobao.360.cn/learning/detail/3113.html)
+ [Heap overflow using unlink](https://sploitfun.wordpress.com/2015/02/26/heap-overflow-using-unlink/?spm=a313e.7916648.0.0.x4nzYZ)
+ [Linux堆溢出漏洞利用之unlink](https://jaq.alibaba.com/community/art/show?spm=a313e.7916646.24000001.74.ZP8rXN&articleid=360)
+ [Linux堆溢出之Fastbin Attack实例详解](http://bobao.360.cn/learning/detail/3996.html)
+ [unsorted bin attack分析](http://bobao.360.cn/learning/detail/3296.html)
+ [Double Free浅析](http://www.vuln.cn/6172)
+ [Understanding the heap by breaking it](http://www.blackhat.com/presentations/bh-usa-07/Ferguson/Whitepaper/bh-usa-07-ferguson-WP.pdf)
+ [An Introduction to Use After Free Vulnerabilities](https://www.purehacking.com/blog/lloyd-simon/an-introduction-to-use-after-free-vulnerabilities)
+ [Use After Free漏洞浅析](http://bobao.360.cn/learning/detail/3379.html?utm_source=tuicool&utm_medium=referral)
+ [Linux堆漏洞之Use after free实例](http://d0m021ng.github.io/2017/03/04/PWN/Linux堆漏洞之Use-after-free实例/)
+ [堆之House of Spirit](http://bobao.360.cn/learning/detail/3417.html)

## 格式化字符串漏洞
+ [Exploiting Format String Vulnerabilities](https://crypto.stanford.edu/cs155old/cs155-spring08/papers/formatstring-1.2.pdf)
+ [二进制漏洞之——邪恶的printf](http://cb.drops.wiki/drops/binary-6259.html)
+ [漏洞挖掘基础之格式化字符串](http://cb.drops.wiki/drops/papers-9426.html)
+ [格式化字符串漏洞利用小结（一）](http://bobao.360.cn/learning/detail/3654.html)
+ [格式化字符串漏洞利用小结（二）](http://bobao.360.cn/learning/detail/3674.html)
+ [Linux下的格式化字符串漏洞利用姿势](http://www.cnblogs.com/Ox9A82/p/5429099.html)
+ [Linux系统下格式化字符串利用研究 ](http://0x48.pw/2017/03/13/0x2c/?utm_source=tuicool&utm_medium=referral)
+ [Advances in format string exploitation](http://phrack.org/issues/59/7.html)
+ [Exploiting Sudo format string vunerability](http://www.vnsecurity.net/research/2012/02/16/exploiting-sudo-format-string-vunerability.html)

## 其余漏洞

### FSP溢出

+ [Head First FILE Stream Pointer Overflow](http://wooyun.jozxing.cc/static/drops/binary-12740.html)
+ [abusing the FILE structure](https://outflux.net/blog/archives/2011/12/22/abusing-the-file-structure/)
+ [File Stream Pointer Overflows Paper.](http://repo.thehackademy.net/depot_ouah/fsp-overflows.txt)
+ [溢出利用FILE结构体](http://bobao.360.cn/learning/detail/3219.html)

### 整数溢出

+ [整数溢出漏洞](http://blog.csdn.net/wuxiaobingandbob/article/details/44618925)

## 保护绕过

### Cannary绕过

+ [栈溢出之绕过CANARY保护 ](http://0x48.pw/2017/03/14/0x2d/)
+ [论canary的几种玩法](http://veritas501.space/2017/04/28/论canary的几种玩法/)
+ [Liunx下关于绕过cancry保护总结](http://yunnigu.dropsec.xyz/2017/03/20/Liunx下关于绕过cancry保护总结/)

## 内核
+ [Introduction to Windows Kernel Driver Exploitation (Pt. 1) - Environment Setup](Introduction to Windows Kernel Driver Exploitation (Pt. 1) - Environment Setup)
+ [Introduction to Windows Kernel Driver Exploitation (Pt. 2) - Stack Buffer Overflow to System Shell](https://glennmcgui.re/introduction-to-windows-kernel-driver-exploitation-pt-2/)
+ [HackSysExtremeVulnerableDriver](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver)
+ [Starting with Windows Kernel Exploitation – part 1 – setting up the lab](https://hshrzd.wordpress.com/2017/05/28/starting-with-windows-kernel-exploitation-part-1-setting-up-the-lab/)
+ [Starting with Windows Kernel Exploitation – part 2 – getting familiar with HackSys Extreme Vulnerable Driver](https://hshrzd.wordpress.com/2017/06/05/starting-with-windows-kernel-exploitation-part-2/)
+ [利用WinDbg本地内核调试器攻陷 Windows 内核](http://bobao.360.cn/learning/detail/4477.html)
+ [Windows内核利用之旅：熟悉HEVD（附视频演示）](http://bobao.360.cn/learning/detail/4002.html)
+ [Windows 内核攻击：栈溢出](http://bobao.360.cn/learning/detail/3718.html)
+ [Linux 内核漏洞利用教程（一）：环境配置](http://bobao.360.cn/learning/detail/3700.html)
+ [Linux 内核漏洞利用教程（二）：两个Demo](http://bobao.360.cn/learning/detail/3702.html)
+ [Linux 内核漏洞利用教程（三）：实践 CSAW CTF 题目](http://bobao.360.cn/learning/detail/3706.html)
+ [Linux内核ROP姿势详解\(一\) ](http://www.freebuf.com/articles/system/94198.html)
+ [Linux内核ROP姿势详解（二）](http://www.freebuf.com/articles/system/135402.html)

## 虚拟机逃逸
+ [Phrack: VM escape - QEMU Case Study](https://www.exploit-db.com/papers/42883/)
+ [虚拟机逃逸——QEMU的案例分析（一）](http://bbs.pediy.com/thread-217997.htm)
+ [虚拟机逃逸——QEMU的案例分析（二）](http://bbs.pediy.com/thread-217999.htm)
+ [虚拟机逃逸——QEMU的案例分析（三） ](http://bbs.pediy.com/thread-218045.htm)

## ARM

+ [ARM 汇编基础速成1：ARM汇编以及汇编语言基础介绍](http://bobao.360.cn/learning/detail/4070.html)
+ [ARM 汇编基础速成2：ARM汇编中的数据类型](http://bobao.360.cn/learning/detail/4075.html)
+ [ARM 汇编基础速成3：ARM模式与THUMB模式](http://bobao.360.cn/learning/detail/4082.html)
+ [ARM 汇编基础速成4：ARM汇编内存访问相关指令](http://bobao.360.cn/learning/detail/4087.html)
+ [ARM 汇编基础速成5：连续存取](http://bobao.360.cn/learning/detail/4097.html)
+ [ARM 汇编基础速成6：条件执行与分支](http://bobao.360.cn/learning/detail/4104.html)
+ [ARM 汇编基础速成7：栈与函数](http://bobao.360.cn/learning/detail/4108.html)

## 进程注入

+ [10种常见的进程注入技术的总结](http://bobao.360.cn/learning/detail/4131.html)
+ [系统安全攻防战：DLL注入技术详解 ](http://www.freebuf.com/articles/system/143640.html)

## 漏洞挖掘
+ [看我如何对Apache进行模糊测试并挖到了一个价值1500刀的漏洞](http://bobao.360.cn/learning/detail/4213.html)

## CTF中的pwn

+ [pwn & exploit](https://github.com/jmpews/pwn2exploit)

### 入门

+ [跟我入坑PWN第一章](http://bobao.360.cn/learning/detail/3300.html)
+ [跟我入坑PWN第二章](http://bobao.360.cn/learning/detail/3339.html)

### 技巧

+ [借助DynELF实现无libc的漏洞利用小结](http://bobao.360.cn/learning/detail/3298.html?utm_source=tuicool&utm_medium=referral)
+ [what DynELF does basically ](http://o0xmuhe.me/2016/12/24/what-DynELF-does-basically/)
+ [Finding Function's Load Address ](http://uaf.io/exploitation/misc/2016/04/02/Finding-Functions.html)

### 总结

+ [CTF总结](https://github.com/stfpeak/CTF)
+ [pwn tips](http://skysider.com/?p=223)
+ [CTF-pwn-tips](https://github.com/Naetw/CTF-pwn-tips)
+ [pwn 学习总结](http://www.angelwhu.com/blog/?p=460)
+ [CTF中做Linux下漏洞利用的一些心得](http://www.cnblogs.com/Ox9A82/p/5559167.html)
+ [linux常见漏洞利用技术实践](http://drops.xmd5.com/static/drops/binary-6521.html)

### WP
+ [堆溢出学习之0CTF 2017 Babyheap ](http://0x48.pw/2017/08/01/0x36/)
+ [一道有趣的CTF PWN题](http://bobao.360.cn/learning/detail/3189.html)
+ [Exploit-Exercises Nebula全攻略](https://github.com/1u4nx/Exploit-Exercises-Nebula)
+ [三个白帽之从pwn me调试到Linux攻防学习](http://wooyun.jozxing.cc/static/drops/binary-16700.html)

# Android Security
## Exercise
+ [DIVA Android](https://github.com/payatu/diva-android/)
+ [Android安全项目入门篇](https://mp.weixin.qq.com/s?__biz=MzI4NjEyMDk0MA==&mid=2649846643&idx=1&sn=0286e8f1b3e6da0acbd129cb248eac2a)

## Skill
+ [Android应用逆向工程](http://bobao.360.cn/learning/detail/4428.html)
+ [初探 Android SO 开发](http://www.ikey4u.com/blog/android-develop/android-so/)
+ [Android App漏洞学习（一）](https://mp.weixin.qq.com/s?__biz=MzI5MDQ2NjExOQ==&mid=2247484642&idx=1&sn=d34ec8b6fc9b5a63b627316e13821b13&chksm=ec1e34cadb69bddc80598c93a0aef429d0b1d668b4fc6e5e6b31a7a3ebfa713aafda1f1b8f7a&scene=21#wechat_redirect)
+ [Android App漏洞学习（二） ](https://mp.weixin.qq.com/s?__biz=MzI5MDQ2NjExOQ==&mid=2247484706&idx=1&sn=eb49d5f71f89fd4d2e3bec23c44c0ae6&chksm=ec1e350adb69bc1c9f775bfaf997459e1cfa3beb065f553ed90fbd88220d7739487e9f7208bd#rd)
+ [WIKI: Android](http://wiki.ioin.in/sort/android)
+ [Android组件安全](https://mp.weixin.qq.com/s?__biz=MzI5MDQ2NjExOQ==&mid=2247484387&idx=1&sn=7264428205276452d40c1ef7b1ed0dcc&chksm=ec1e33cbdb69badd00794f81caa43e5d62e0dc9bb7b9baa9d4c3c9eb64a3a0a18613356bf584#rd)
+ [通过 WebView 攻击 Android 应用](https://zhuanlan.zhihu.com/p/28107901)

## Tool
+ [走到哪黑到哪——Android渗透测试三板斧](http://bobao.360.cn/learning/detail/4254.html)
+ [Brida:将frida与burp结合进行移动app渗透测试](http://www.4hou.com/penetration/6916.html)

# 浏览器安全
+ [浅谈多浏览器的自动化测试](http://www.freebuf.com/articles/others-articles/145586.html)
+ [浏览器漏洞挖掘思路](https://zhuanlan.zhihu.com/p/28719766)
+ [IE漏洞攻防编年简史](http://blog.topsec.com.cn/ad_lab/ie%E6%BC%8F%E6%B4%9E%E6%94%BB%E9%98%B2%E7%BC%96%E5%B9%B4%E7%AE%80%E5%8F%B2/)
+ [IE浏览器漏洞综合利用技术：UAF利用技术的发展](http://bobao.360.cn/learning/detail/3666.html)
+ [IE浏览器漏洞综合利用技术：堆喷射技术](http://bobao.360.cn/learning/detail/3656.html)
+ [cure53-browser-sec-whitepaper](https://github.com/cure53/browser-sec-whitepaper)
+ [X41-Browser-Security-White-Paper.pdf](https://browser-security.x41-dsec.de/X41-Browser-Security-White-Paper.pdf)

# IOS/OSX Securiy
+ [OSX/iOS reverse engineering](https://github.com/michalmalik/osx-re-101)

## IOS
### Exercise
+ [Damn Vulnerable iOS Application (DVIA)](http://damnvulnerableiosapp.com/#trainings)

### Skill
+ [IosHackStudy](https://github.com/pandazheng/IosHackStudy)
+ [Papers, Slides and Thesis Archive : iOS](https://papers.put.as/ios/ios/)
+ [ios-wiki: iOS Security](http://security.ios-wiki.com/)
+ [apple官方文档：iOS Security](https://www.apple.com/business/docs/iOS_Security_Guide.pdf)
+ [iOS安全系列汇总](http://esoftmobile.com/2014/02/14/ios-security/)
+ [浅谈iOS应用安全自动化审计](https://security.tencent.com/index.php/blog/msg/105)
+ [iOS安全审计入门](http://www.freebuf.com/articles/terminal/123098.html)
+ [iOS内核漏洞挖掘–fuzz&代码审计](http://blog.pangu.io/xkungfoo2015/)

## OSX
### Exercise
+ [OS X : Crackmes](https://reverse.put.as/crackmes/)

### Skill
+ [Papers, Slides and Thesis Archive : Mac OS X](https://papers.put.as/macosx/macosx/)
+ [实现 macOS 内核监控的几种方法](https://paper.seebug.org/380/)

# 蓝牙安全
+ [Guide to Bluetooth Security](https://csrc.nist.gov/csrc/media/publications/sp/800-121/rev-2/draft/documents/sp800_121_r2_draft.pdf)