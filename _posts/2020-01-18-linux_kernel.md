---
layout: single
title:  "Linux Kernel Exploitation part 1"
date:   2020-01-01
toc: true
toc_label: Table
toc_sticky: true
classes: wide

---

## Description

lab10c is a simple lab provided by RPI Sec to demonstrate how the Linux Kernel can be exploited.It was intentionally left a gap to gain root privilege accesss using a null pointer dereferences exists in their module. NULL pointer dereference it occurs when the *ptr does not point to any valid memory address. 

## Exploitation technique 

In fact , there is no risk in userspace for the NULL pointer de-reference , however in Kernel space null pointer it means a zero which it will defiantly be considered as a valid address. The common technique that used widely is using mmap() syscall to map the 0 address then , move subsquence assembly code into  0 address using **memcpy** for instance , the payload will give the current process a root privilege. **commit_creds ( prepare_kernel_cred (0));** 
## Vulnerability Module 

[lab10c](https://raw.githubusercontent.com/RPISEC/MBE/master/src/lab10/lab10C.c)


## Exploit 
<script src="https://gist.github.com/0x43434343/2db433dc0fd54a699dd97895403c1342.js"></script>



<img src="{{ site.url }}{{ site.baseurl }}/assets/images/null_ptr.jpg" alt="">
