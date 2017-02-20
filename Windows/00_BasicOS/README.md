Examples:

| File                            | Description                                                         |
| --------------------------------| ------------------------------------------------------------------- |
| 00\_pe\_return\_00.asm          | Simple idiomatic fasm example. Returns 42.                          |
| 00\_pe\_return\_01.asm          | Assembled bindump of 00\_pe\_return.exe                             |
| 00\_pe\_return\_02.asm          | Label important PE locations; print to verify                       |
| 00\_pe\_return\_03.asm          | Calculate padding; Name values; Replace addresses with labels.      |
| 00\_pe\_return\_04.asm          | Dissassemble code at 'start' label.                                 |
| 00\_pe\_return\_05.asm          | Calculate rip-relative addresses replacing hard-coded value.        |
| 00\_pe\_return\_06.asm          | Alternative: Replace pointers with absolute addresses.              |
| 01\_pe\_printf\_00.asm          | Add msvcrt.dll and call printf to 00\_pe\_return\_05.asm            |
| 01\_pe\_printf\_01.asm          | Add BSS section.                                                    |
| 01\_pe\_printf\_02.asm          | Print call return address from stack. (Demo stack offset.)          |
| 02\_pe\_messagebox\_00.asm      | Add GUI Subsystem, call GetModuleNameA and MessageBoxA              |
| 02\_pe\_messagebox\_01.asm      | Put IDATA into CODE section; Remove padding; Remove DOS program     |
| 02\_pe\_messagebox\_02.asm      | Let assembler calculate rip-relative addresses inside section.      |
| 02\_pe\_messagebox\_03.asm      | Embed BSS inside CODE section.                                      |
| #todo                           | Raw PE DLL, GUI mode, shows message box                             |
| #todo                           | Raw PE EXE, GUI mode, calls message box DLL                         |
| #todo                           | Raw PE EXE, CUI mode, parameter variations calling convention       |
| #todo                           | Raw PE EXE, CUI mode, profiling                                     |
| #todo                           | Raw PE EXE, CUI mode, threads                                       |
| #todo                           | Raw PE EXE, CUI mode, thread local storage                          |
| #todo                           | Raw PE EXE, CUI mode, UNICODE                                       |
| #todo                           | Raw PE EXE, CUI mode, users                                         |
| #todo                           | Raw PE EXE, CUI mode, service                                       |
