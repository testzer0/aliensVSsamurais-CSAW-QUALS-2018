# aliensVSsamurais-CSAW-QUALS-2018
aliensVSsamurais is the binary; sploit4.py is the exploit.
Uses an offset hardcoded for my system, change it before use.

# Synopsis
No checks on index in rename_alien ==> arbitrary read/write primitive.
Leak address of libc, and calculate address of system.
Overwrite _strtoul@got.plt with &system.
Send "/bin/sh\x00" as choice.
Spawn shell.
Due to NULL termination, mangles exit@got.plt. Hence use kill [PID] to exit.
