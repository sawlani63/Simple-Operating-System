# Simple-Operating-System

Simple Operating System, or SOS, is designed to be a robust operating system built on top of the seL4 microkernel. As such, it functions using a small number of core mechanisms provided by the microkernel, such as virtual address spaces, threads, and inter-process communication. By further abstracting these mechanics, it aims to offer UNIX-like functionalities through a similar system call interface, managing resources using abstractions such as virtual memory and a virtual file system.

The main purpose of Simple Operating System (SOS) which is built on top of seL4, is to offer UNIX-like functionalities by maintaining concrete abstractions such as address spaces, virtual memory, and a virtual file system. SOS should also support demand paging as well as running multiple processes concurrently. Every component within SOS should be high-performance and bench-marked to ensure consistency.

Building on these abstractions, we aim to offer users an intuitive set of system calls that streamline essential operations. These include file operations such as open, close, read, write, and stat; time-based functions like sleep and get system time; process-related commands for creating, deleting, retrieving IDs, checking status, and waiting on processes; as well as directory-related functions like getdirent for retrieving directory entries.
        
While no prior knowledge of the seL4 microkernel is assumed, a basic understanding of the inner workings of various data structures and operating systems is expected, including why the demonstrated abstractions are necessary and relevant UNIX behaviours.

Note that this operating system was built on some minimal preexisting user-level code and any files or libraries not changed by myself have not been included in this project. As such, the project cannot simply be cloned and launched as of this current time because of a lack of its dependencies. 

However, the source code of the project is publicly available at https://github.com/SEL4PROJ/AOS
