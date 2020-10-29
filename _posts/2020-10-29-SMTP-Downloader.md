---
layout: post
title: SMTP Mailer and Downloader - Part 1
---

This is a writeup on reversing a worm type of malware that can be found [here](https://github.com/fabrimagic72/malware-samples/blob/master/Downloader-CUZ/smb-7teux2sm.zip).
I usually begin my analysis by uploding the sample to VirusTotal and examining executable file using different tools like PEView, PEStudio, etc, to see if it's packed and to try to understand what it might do to the system by looking at strings and imports.
PEView shows that it is probably not packed, because **Virtual Size** and **Raw Data Size** for every header of the executable are almost the same. We can confirm that it is not packed by looking at **IMPORT Address Table** of the .rsrc header that shows too many functions. Packed malware usually imports just couple of functions like *LoadLibraryA* and *GetProcAddress*.

![PEView](/images/SMTP_Worm/peviewimg.JPG)

Upon loading the sample in 'PE Studio', there are 7 indicators that the sample is probably malicious. 29 imports and 23 strings which can be used to try to 
figure out what the sample might do when executed. There are even some IPs listed: 209.85.223.33, 209.85.210.24 and 209.85.223.27.

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
