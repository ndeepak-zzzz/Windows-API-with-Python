# Windows-API-with-Python
Hacking the Windows API with Python - Real Ethical Hacking
## Windows Internals Overview
### Processes and Threads :- 
* Process is presently running/executing programs,
* Process contains at least 1 thread,
* Process and threads has its own virtual memory space for that particular process is self-contained to itself, which means other process cant interfere in other process without some privileges.
* thread runs inside of a process
* OS allocates processing time to CPU to each threads(Thread poolings and others) .
* Each thread executes code based on the PE/EXE file ran
* Threads can create more threads that run different code.    
    [More in Process and threads](https://docs.microsoft.com/en-us/windows/win32/procthread/processes-and-threads)

### Token
* Every process has an access token/Security context/Access Token
* Used to deal with privileges or access rightd for a process or thread
* Contains some of the following:-
    * Privileges
    * User Groups
    * Types of Token
    * Defaults Access Control Lists(DACL's)
    
### How Are Tokens Used?
* Tokens are passed/used in every Windows API calls
* Most normally passed by reference(Pointers in C/C++ concepts)
    * Reference: Memory Location is passed instead or raw token structure
* Access to API calls, files, memory, etc is all based on the processes tokens,
* No new privileges can be added to made token, it has to be rebuilt from scratch which means there's should be new process to be occured.
#### Points:-
* You can't add permissions to a token, but can take them away.
* You can enable and disable ones that are already present but you cannot add to it.

### Handle
* Handle is an abstract object that points to the memory location of another object(similar to pointer)
* Normally points to a process, processes token, raw data, etc.

### Windows Structures
* It is an abstract structure in memory to hold data in a specific way
* Normally used with Windows API Calls
* It can be passed to a call or returned from a call
#### C++
~~~
typedef struct _PROCESS_INFORMATION{
        HANDLE HProcess;
        HANDLE hThread;
        DWORD dwProcessID;
        DWORD dwThreadID;
} PROCESS_ INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;
~~~
