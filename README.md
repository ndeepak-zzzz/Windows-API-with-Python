# Windows-API-with-Python
Hacking the Windows API with Python - Real Ethical Hacking
## Windows Internals Overview
### Processes and Threads :- 
* Presently running programs
* contains at least 1 thread
* process has its own virtual memory space
* thread runs inside of a process
* OS allocates processing time to each threads 
* Executes code based on the PE/EXE file ran
* Threads can create more threads and run different code
    
    [More in Process and threads](https://docs.microsoft.com/en-us/windows/win32/procthread/processes-and-threads)

### Token
* Security context/Access Token
* Used to deal with privileges or access rightd for a process or thread
* Containss some of the following:-
    * Privileges
    * User Groups
    * Types of Token
    * Defaults Access Control Lists(DACL's)
    
