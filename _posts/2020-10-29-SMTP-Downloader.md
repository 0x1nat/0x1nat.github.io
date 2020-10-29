---
layout: post
title: SMTP Mailer and Downloader - Part 1
---

This is a writeup on reversing a worm type of malware that can be found [here](https://github.com/fabrimagic72/malware-samples/blob/master/Downloader-CUZ/smb-7teux2sm.zip).
I usually begin my analysis by uploding the sample to VirusTotal and examining executable file using different tools like PEView, PEStudio, etc, to see if it's packed and to try to understand what it might do to the system by looking at strings and imports.
*PEView* shows that it is probably not packed, because **Virtual Size** and **Raw Data Size** for every header of the executable are almost the same. We can confirm that it is not packed by looking at **IMPORT Address Table** of the .rsrc header that shows too many functions. Packed malware usually imports just couple of functions like **LoadLibraryA** and **GetProcAddress**.

![PEView](/images/SMTP_Worm/peviewimg.JPG)

Upon loading the sample in *PE Studio*, there are 7 indicators that the sample is probably malicious. 29 imports and 23 strings which can be used to try to 
figure out what the sample might do when executed. There are even some IPs listed: *209.85.223.33*, *209.85.210.24* and *209.85.223.27*.

![PE Studio](/images/SMTP_Worm/pestudioimg.JPG)

Next step is to load IDA and begin static analysis, which shouldn't be too hard because the sample is not packed.
After starting up, IDA automatically detects the **WinMain** function.

![WinMain](/images/SMTP_Worm/idawinmain.JPG)

The first call we see, **WSAStartup**, is the API function which initiates use of Winsock DLL by current process, enabling Windows Socket functionality.
The following function is defined by worm author and it  loads different libraries (DLLs) and exported functions from those libraries during run-time:
* NetApi32.dll
* Mpr.dll
* WNetCancelConnection2A
* WNetAddConnection2A
* NetApiBufferFree
* NetUserEnum

I gave it the name **mw_runtime_linking_libraries** for easier understanding and also did that for every other examined function.

**GetModuleFileNameA** will retrieve the path of the executable file of the current process, because first argument (hModule) is 0 (NULL) and it will be stored into *Filename* variable.
Next two functions, **GetUserNameA** and **_strupr**, are responsible for getting the name of the user associated with the current thread and changing it to 
upper case which is stored in the memory afterwards.
The last function, in the image above, is just a wrapper function for other calls. The code for that function can be seen below:

![mw_allocate_two_heaps](/images/SMTP_Worm/mw_allocating_two_heaps.JPG)

The first of those two functions is not doing anything at the beginning, because value of the variable *second_heap_address* is zero and the execution is 
terminated immediately by jumping to the 'loc_401028':

![Check if gmail.com in second allocated memory](/images/SMTP_Worm/mw_check_if_gmail_com_in_second_heap_1.JPG)

The other one is a wrapper for the code that is responsible for sending DNS request.

![Dns query wrapper](/images/SMTP_Worm/mw_dns_query_wrapper.JPG)

**mw_dns_query** function uses API call **GetModuleHandleA** to check if *dnsapi.dll* library is loaded and if it isn't it loads it by calling **LoadLibraryA**. After library is loaded, **GetProcAddress** call is used to get **DnsQuery_A** function from the library.

![Dns query](/images/SMTP_Worm/mw_dns_query_1.JPG)

**DnsQuery_A** function, which is stored in *EAX* register, sends DNS query request to get mail server of the *google.com* domain name (*gmail.com* used for some reason). The result is stored in *ppQueryResults*, which is a list, because there could be multiple records returned.

![](/images/SMTP_Worm/dnsquery_a.JPG)

There is a check weather *ppQueryResult* is NULL or not. If it is NULL, that means that the list is empty, there are no records and function terminates.
If it's not NULL, type of the first record (first item in the *ppQueryResults* list) is checked. If the type is not *0xF* (**DNS_MX_RECORD**), 
record is skipped and list pointer points to the next record (*loc_4034D8*). The logic is repeated until MX RECORD is found or the pointer is equal to NULL (list empty).
If there is a MX RECORD in the list, API calls **GetProcessHeap** and **HeapAlloc** are called and memory is allocated on the heap.
Newly allocated memory is zero initialized which is done by ***rep stosd*** assembly instruction. For *ECX* repetitions (*ECX* = 42h = 66 dec) store
the contents of *EAX* to where *EDI* points to (*EDI* points to allocated memory).
Basically **memset(*EDI*, 0, 264)**.
Then by calling **lstrcpynA** function, address of the mail server which is ***mail.evil2.com*** is copied to allocated memory
(Im using FakeNet-NG to fake internet connection and that tool returns mail.evil2.com as mail server by default every time) and also value *A* 
is written at 4 bytes from the beginning of that memory location. Return value of the function is the address of the newly allocated memory.

![](/images/SMTP_Worm/dns_records_list.JPG)

If the return address is not NULL, **mw_dns_query_wrapper_func** terminates, again returning the same address (look at the 5th image from the top).
There is one more check if that memory is NULL and if that's negative, next part of the code is executed:

![](/images/SMTP_Worm/mw_second_heap.JPG)

First of these two functions begin with check if pointer variable *second_heap_address* is NULL. Because this is the first run of the sample 
it is NULL.

![](/images/SMTP_Worm/second_heap_begin.JPG)

Code proceeds with allocating 96 bytes of data on the heap and zero initializing it with the use of ***rep stosd*** as before.
*gmail.com* is moved into *ECX* register and the address of allocated memory from the previous function is also moved into *EAX* register.
Next by calling **lstrcpynA** *gmail.com* is copied to newly allocated memory, and by calling ***mov [ESI+4], eax***, the address of the first allocated memory is 
written in the new one, 4 bytes from the beggining. Also by calling **GetTickCount** API function, number of elapsed seconds since system was started is also written in the same memory.
Finally the address of allocated memory is saved into global variable *second_heap_address*.

![](/images/SMTP_Worm/second_heap_mid.JPG)

Next function, **mw_check_if_gmail_com_in_second_heap**, is a short one. It checks if global variable that holds address to the second allocated memory is NULL, 
and if it's not, it reads *gmail.com* from that memory and compares it with *gmail.com* string that was sent as an argument. Function **lstrcmpiA** is used for comparison. If those two values are the same, function terminates returning the address of second allocated memory.

![](/images/SMTP_Worm/mw_compare_gmail.JPG)

*EAX* holds returned memory address, and the value at *EAX+5ch* is incremented from 0 to 1.

![](/images/SMTP_Worm/5c_from_0_to_1.JPG)

After loading libraries, making DNS request, allocating two memory locations on the heap, code checks if the user that ran the exe is *SYSTEM*.
It does that by comparing bytes of previously stored name in memory, one that came from **GetUserNameA** API call, with the bytes of *SYSTEM* string. 
If the user is *SYSTEM*, it proceeds with the execution.

![](/images/SMTP_Worm/check_if_system.JPG)

First function after confirmation that the user is *SYSTEM* extracts data from the resource part of the executable. *Resource Hacker* tool shows that 
there are two resources and one of them looks like an executable because of the **MZ** file signature. The other one doesn't have a known file signature 
but code in IDA will prove that it is the second part of the same payload.

![](/images/SMTP_Worm/resourcehacker.JPG)

The function calls **FindResourceA**, **LoadResource** and **LockResource** two times, for two different resources and stores addresses of those two resources 
in memory at two different locations (variables).

![](/images/SMTP_Worm/loading_resources.JPG)

**GetSystemDirectory** API call gets path to system directory and stores it into variable (because this is 32bit executable, that directory is *C:\\Windows\\SysWOW64* even though the call will return *C:\\windows\\system32*).

![](/images/SMTP_Worm/getsystemdir.JPG)

Next, code appends string *\\lsasvc.exe* to *C:\\windows\\system32* and creates that file with write permissions by calling api function **CreateFileA**.

![](/images/SMTP_Worm/create_file_1.JPG)

Then first part of the payload (resource with **MZ** file signature) is written to that file and there is a loop that will append the other resource to 
the same file, part by part (because the other resource is much bigger than the first one). At the end, handle to the file is closed and the payload is completely written to *C:\\Windows\\SysWOW64\\lsasvc.exe*.

![](/images/SMTP_Worm/loop_append_resource.JPG)
