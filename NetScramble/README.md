# how to use `iphlpapi.h`
An order of writing libraries is important.  
`winsock2.h` has to be written prior to `windows.h`.  
OK
```c
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")
```
NG: encounter build error
```c
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")
```
- cf.
    - https://www.geekpage.jp/programming/iphlpapi/
    - https://kashiwaba-yuki.com/windows-windbg-010-socket#winsock2