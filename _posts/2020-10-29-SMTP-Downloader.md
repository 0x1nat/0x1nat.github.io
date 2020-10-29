---
layout: post
title: SMTP Mailer and Downloader - Part 1
---

This is a writeup on reversing a worm type of malware that can be found [here](https://github.com/fabrimagic72/malware-samples/blob/master/Downloader-CUZ/smb-7teux2sm.zip).
I usually begin my analysis by examining executable file using different tools like PEView, PEStudio, etc, to see if it's packed and to try to understand what it might do to the system by looking at strings and imports.
PEView shows that it is probably not packed, because **Virtual Size** and **Raw Data Size** for every header of the executable are almost the same. We can confirm that it is not packed by looking at **IMPORT Address Table** of the .rsrc header that shows too many functions. Packed malware usually imports just couple of functions like *LoadLibraryA* and *GetProcAddress*.

