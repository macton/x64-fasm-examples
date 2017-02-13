format PE64 console 
entry start 
include 'win64a.inc' 

section '.code' code readable executable 
start: 

  mov eax, 42

  exit:
	  invoke	ExitProcess, eax

section '.idata' import data readable writeable 

library kernel32,'kernel32.dll',\ 
        msvcrt,  'msvcrt.dll' 

import kernel32,\ 
       ExitProcess,       'ExitProcess', \
       GetModuleFileName, 'GetModuleFileNameA' 

import msvcrt, \ 
       printf, 'printf', \
       strlen, 'strlen', \
       scanf,  'scanf' 
