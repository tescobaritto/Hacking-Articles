Hi, today i will tell you a bit about windows privlege escalation this article will be based of TCM course and aditional resources also my expirience although limited
## Kernel Based Privlege Escalation
### What is Kernel
Kernel is computer program at the core of computer's operating system and usually have a complete control over everything in the system. It is acting as a bridge between hardware and software. It is the portion of the operating system code that is always resident in memory and facilitates interactions between hardware and software components. A full kernel controls all hardware resources (e.g. I/O, memory, cryptography) via device drivers, arbitrates conflicts between processes concerning such resources, and optimizes the utilization of common resources e.g. CPU & cache usage, file systems, and network sockets.                                                       

The critical code of the kernel is usually loaded into a separate area of memory, which is protected from access by application software or other less critical parts of the operating system

![Kernel_Layout svg](https://github.com/user-attachments/assets/5ff10f2b-f84a-4d02-8cb2-a62114d4f1d8)

(source wikipedia)
### Kernel PE
Kernel privilege escalation involves exploiting vulnerabilities in the operating system kernel to gain elevated privileges, often allowing an attacker to move from a low-privileged user to a root or SYSTEM-level account. This technique is critical in penetration testing because the kernel governs core system functions, making it a high-value target for attackers.                                                 

Operating systems separate processes into two modes: user mode and kernel mode. User mode restricts access to critical system resources and prevents direct hardware interaction. Kernel mode, on the other hand, has unrestricted access to hardware and system memory, allowing it to perform privileged tasks. When a low-privileged user process interacts with the kernel, it does so via system calls. If vulnerabilities exist in how the kernel handles these calls, they can be exploited to escalate privileges.

Attackers typically leverage these vulnerabilities to execute malicious code in the kernel's context, bypassing security controls like Access Control Lists (ACLs) or sandbox restrictions. This often leads to full control over the system, making kernel privilege escalation a powerful post-exploitation technique.
### Dirty Cow (CVE-2016-5195)
Dirty COW (CVE-2016-5195) is a renowned Linux kernel vulnerability that allows privilege escalation through a race condition in the copy-on-write (COW) mechanism. Discovered in 2016, this flaw exists because the kernel improperly handles memory permissions when processes attempt to write to read-only memory mappings.

In practice, an attacker can exploit Dirty COW by mapping a critical system file, such as /etc/passwd, into memory as read-only. By racing the kernel’s copy-on-write mechanism with rapid, repeated writes, they can overwrite the original file in memory without proper permission checks. This allows modifications like adding a new root user, granting the attacker full system access.

This vulnerability was significant because it had existed undetected for nearly a decade, affecting a vast number of Linux distributions and kernel versions. Exploitation was straightforward, with public proof-of-concept code demonstrating the attack’s effectiveness.

To mitigate the issue, Linux developers released patches promptly after its disclosure in late 2016. Administrators were urged to update kernels and employ security frameworks like SELinux to limit potential exploitation. Dirty COW remains a textbook example of how kernel flaws can be exploited to bypass user-mode restrictions and gain elevated privileges.
