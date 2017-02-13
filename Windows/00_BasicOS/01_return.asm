; 01_return.asm
; Simple fasm example. Returns 42.
;   - Why 42? Check out: http://www.muppetlabs.com/~breadbox/software/tiny/return42.html

format PE64 console 
entry start 
include 'win64a.inc' 

section '.code' code readable executable 
start: 

  mov eax, 42

  exit:
	  invoke	ExitProcess, eax

section '.idata' import data readable writeable 

library kernel32,'kernel32.dll'

import kernel32,\ 
  ExitProcess,       'ExitProcess'
