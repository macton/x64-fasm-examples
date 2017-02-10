; 01_div.asm
;
; fasm 01_div.asm 01_div
; chmod u+x 01_div
; ./01_div

use64 
org 0x01400000
BSS_SIZE = 0x100000 ; 1MB

ELF64:
  .EHEADER_SIZE       = 64
  .PHEADER_ENTRY_SIZE = 56 

EHDR:
  ; e_type
  ;   This member identifies the object file type.
  .ET_NONE   = 0       ; No file type
  .ET_REL    = 1       ; Relocatable file
  .ET_EXEC   = 2       ; Executable file
  .ET_DYN    = 3       ; Shared object file
  .ET_CORE   = 4       ; Core file
  .ET_LOOS   = 0xfe00  ; Operating system-specific
  .ET_HIOS   = 0xfeff  ; Operating system-specific
  .ET_LOPROC = 0xff00  ; Processor-specific
  .ET_HIPROC = 0xffff  ; Processor-specific

  ; e_machine
  ;   This member's value specifies the required architecture for an individual file.
  .EM_X86_64      = 62

  ; e_version
  ;   This member identifies the object file version.
  .EV_NONE     = 0 ; Invalid version
  .EV_CURRENT  = 1 ; Current version

  ; e_entry
  ;   This member gives the virtual address to which the system first transfers control, thus starting the process. 
  ;   If the file has no associated entry point, this member holds zero.
  ; e_phoff
  ;   This member holds the program header table's file offset in bytes. If the file has no program header table, 
  ;   this member holds zero.
  ; e_shoff
  ;   This member holds the section header table's file offset in bytes. If the file has no section header table, 
  ;   this member holds zero.
  ; e_flags
  ;   This member holds processor-specific flags associated with the file. Flag names take the form EF_machine_flag.
  ; e_ehsize
  ;   This member holds the ELF header's size in bytes.
  ; e_phentsize
  ;   This member holds the size in bytes of one entry in the file's program header table; all entries are the same size.
  ; e_phnum
  ;   This member holds the number of entries in the program header table. Thus the product of e_phentsize and e_phnum
  ;   gives the table's size in bytes. If a file has no program header table, e_phnum holds the value zero.
  ; e_shentsize
  ;   This member holds a section header's size in bytes. A section header is one entry in the section header table; 
  ;   all entries are the same size.
  ; e_shnum
  ;   This member holds the number of entries in the section header table. Thus the product of e_shentsize and e_shnum 
  ;   gives the section header table's size in bytes. If a file has no section header table, e_shnum holds the value zero.
  ;   If the number of sections is greater than or equal to SHN_LORESERVE (0xff00), this member has the value zero and the
  ;   actual number of section header table entries is contained in the sh_size field of the section header at index 0. 
  ;   (Otherwise, the sh_size member of the initial entry contains 0.)
  ; e_shstrndx
  ;   This member holds the section header table index of the entry associated with the section name string table. 
  ;   If the file has no section name string table, this member holds the value SHN_UNDEF.
  .SHN_UNDEF = 0

  ; ELF Header:
  ;   Magic:   7f 45 4c 46 02 01 01 03 00 00 00 00 00 00 00 00 
  ;   Class:                             ELF64
  ;   Data:                              2's complement, little endian
  ;   Version:                           1 (current)
  ;   OS/ABI:                            UNIX - GNU
  ;   ABI Version:                       0
  ;   Type:                              EXEC (Executable file)
  ;   Machine:                           Advanced Micro Devices X86-64
  ;   Version:                           0x1
  ;   Entry point address:               0x400120
  ;   Start of program headers:          64 (bytes into file)
  ;   Start of section headers:          0 (bytes into file)
  ;   Flags:                             0x0
  ;   Size of this header:               64 (bytes)
  ;   Size of program headers:           56 (bytes)
  ;   Number of program headers:         4
  ;   Size of section headers:           0 (bytes)
  ;   Number of section headers:         0
  ;   Section header string table index: 0

  E_IDENT:
    .ELFCLASS64     = 2
    .ELFDATA2LSB    = 1
    .EV_CURRENT     = 1
    .ELFOSABI_LINUX = 3
    .E_IDENT_SIZE   = 16

    db  0x7f, "ELF"              ; e_ident.ELFMAG0-ELFMAG3
    db  E_IDENT.ELFCLASS64       ; e_ident.EI_CLASS
    db  E_IDENT.ELFDATA2LSB      ; e_ident.EI_DATA
    db  E_IDENT.EV_CURRENT       ; e_ident.EI_VERSION
    db  E_IDENT.ELFOSABI_LINUX   ; e_ident.EI_OSABI
    db  0                        ; e_ident.EI_OSABIVERSION
    db  7 dup (0)                ; e_ident.EI_PAD

  assert (($-E_IDENT) = E_IDENT.E_IDENT_SIZE)

  dw  EHDR.ET_EXEC             ; u16 e_type
  dw  EHDR.EM_X86_64           ; u16 e_machine
  dd  EHDR.EV_CURRENT          ; u32 e_version
  dq  start                   ; u64 e_entry
  dq  PHDR - $$                ; u64 e_phoff
  dq  0                        ; u64 e_shoff
  dd  0                        ; u32 e_flags
  dw  ELF64.EHEADER_SIZE       ; u16 e_ehsize
  dw  ELF64.PHEADER_ENTRY_SIZE ; u16 e_phentisize
  dw  4                        ; u16 e_phnum
  dw  0                        ; u16 e_shentsize
  dw  0                        ; u16 e_shnum
  dw  EHDR.SHN_UNDEF           ; u16 e_shstrndx

assert (($-EHDR) = ELF64.EHEADER_SIZE)

PHDR:
  ;  Program Headers:
  ;    Type           Offset             VirtAddr           PhysAddr
  ;                   FileSiz            MemSiz              Flags  Align
  ;    LOAD           0x0000000000000000 0x0000000000400000 0x0000000000000000
  ;                   0x000000000000065c 0x000000000000065c  RWE    100000
  ;    LOAD           0x0000000000000000 0x0000000000600000 0x0000000000600000
  ;                   0x0000000000000000 0x0000000000030000  RW     200000
  ;    INTERP         0x0000000000000640 0x0000000000400640 0x0000000000000000
  ;                   0x000000000000001c 0x000000000000001c  R      1
  ;        [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  ;    DYNAMIC        0x0000000000000550 0x0000000000400550 0x0000000000000000
  ;                   0x0000000000000090 0x0000000000000090  R      8
  ;  

  ; An executable or shared object file's program header table is an array of structures, each describing a segment or
  ; other information that the system needs to prepare the program for execution. An object file segment contains one
  ; or more sections...
  ;
  ; Program headers are meaningful only for executable and shared object files. A file specifies its own program header 
  ; size with the ELF header's e_phentsize and e_phnum members..

  ; p_type
  ;   The kind of segment this array element describes or how to interpret the array element's information.

  .PT_NULL    = 0  ; Unused; other members' values are undefined. This type enables the program header table to contain ignored entries.
  .PT_LOAD    = 1  ; Specifies a loadable segment, described by p_filesz and p_memsz. The bytes from the file are mapped to the beginning 
                   ; of the memory segment. If the segment's memory size (p_memsz) is larger than the file size (p_filesz), the extra
                   ; bytes are defined to hold the value 0 and to follow the segment's initialized area. The file size can not be larger 
                   ; than the memory size. Loadable segment entries in the program header table appear in ascending order, sorted on the 
                   ; p_vaddr member.
  .PT_DYNAMIC = 2  ; Specifies dynamic linking information. See DYNAMIC section.
  .PT_INTERP  = 3  ; Specifies the location and size of a null-terminated path name to invoke as an interpreter. This segment type is 
                   ; mandatory for dynamic executable files and can occur in shared objects. It cannot occur more than once in a file. 
                   ; This type, if present, it must precede any loadable segment entry. See "Program Interpreter" for further information.
  .PT_NOTE    = 4  ; Specifies the location and size of auxiliary information. 
                   ; See https://docs.oracle.com/cd/E19683-01/816-1386/6m7qcoblj/index.html#chapter6-18048
  .PT_SHLIB   = 5  ; Reserved but has unspecified semantics.
  .PT_PHDR    = 6  ; Specifies the location and size of the program header table itself, both in the file and in the memory image of the 
                   ; program. This segment type cannot occur more than once in a file. Moreover, it can occur only if the program header 
                   ; table is part of the memory image of the program. This type, if present, must precede any loadable segment entry. 

  ; A dynamic executable or shared object that initiates dynamic linking can have one PT_INTERP program header element. During exec(2), 
  ; the system retrieves a path name from the PT_INTERP segment and creates the initial process image from the interpreter file's segments. 
  ; The interpreter is responsible for receiving control from the system and providing an environment for the application program.

  ; p_flags
  ;   Flags relevant to the segment.

  .PF_X   = 0x1 ; Execute  
  .PF_W   = 0x2 ; Write  
  .PF_R   = 0x4 ; Read  
  .PF_RW  = .PF_R + .PF_W
  .PF_RWX = .PF_R + .PF_W + .PF_X

  ; p_offset
  ;   The offset from the beginning of the file at which the first byte of the segment resides.
  ; p_vaddr
  ;   The virtual address at which the first byte of the segment resides in memory.
  ; p_paddr
  ;   The segment's physical address for systems in which physical addressing is relevant. Because the system ignores physical addressing 
  ;   for application programs, this member has unspecified contents for executable files and shared objects.
  ; p_filesz
  ;   The number of bytes in the file image of the segment, which can be zero.
  ; p_memsz
  ;   The number of bytes in the memory image of the segment, which can be zero.
  ; p_align
  ;   Loadable process segments must have congruent values for p_vaddr and p_offset, modulo the page size. This member gives the value to 
  ;   which the segments are aligned in memory and in the file. Values 0 and 1 mean no alignment is required. Otherwise, p_align should be a 
  ;   positive, integral power of 2, and p_vaddr should equal p_offset, modulo p_align.

PHDR_INTERP:
  dd  PHDR.PT_INTERP          ; u32 p_type
  dd  PHDR.PF_R               ; u32 p_flags
  dq  INTERP - $$             ; u64 p_offset
  dq  INTERP                  ; u64 p_vaddr
  dq  0                       ; u64 p_paddr
  dq  INTERP.SIZE             ; u64 p_filesz
  dq  INTERP.SIZE             ; u64 p_memsz
  dq  1                       ; u64 p_align

assert (($-PHDR_INTERP) = ELF64.PHEADER_ENTRY_SIZE)

PHDR_DYNAMIC:
  dd  PHDR.PT_DYNAMIC         ; u32 p_type
  dd  PHDR.PF_R               ; u32 p_flags
  dq  DYNAMIC - $$            ; u64 p_offset
  dq  DYNAMIC                 ; u64 p_vaddr
  dq  0                       ; u64 p_paddr
  dq  DYNAMIC.SIZE            ; u64 p_filesz
  dq  DYNAMIC.SIZE            ; u64 p_memsz
  dq  8                       ; u64 p_align

assert (($-PHDR_DYNAMIC) = ELF64.PHEADER_ENTRY_SIZE)

PHDR_LOAD_ELF:
  dd  PHDR.PT_LOAD            ; u32 p_type
  dd  PHDR.PF_RWX             ; u32 p_flags
  dq  0x0                     ; u64 p_offset
  dq  $$                      ; u64 p_vaddr
  dq  0                       ; u64 p_paddr
  dq  FILE.SIZE               ; u64 p_filesz
  dq  FILE.SIZE               ; u64 p_memsz
  dq  0x100000                ; u64 p_align

assert (($-PHDR_LOAD_ELF) = ELF64.PHEADER_ENTRY_SIZE)

PHDR_BSS:
  .BSS_OFFSET = 0x200000
  .BSS_ALIGN  = 0x100000

  dd  PHDR.PT_LOAD              ; u32 p_type
  dd  PHDR.PF_RW                ; u32 p_flags
  dq  0x0                       ; u64 p_offset
  dq  $$ + PHDR_BSS.BSS_OFFSET  ; u64 p_vaddr
  dq  $$ + PHDR_BSS.BSS_OFFSET  ; u64 p_paddr
  dq  0                         ; u64 p_filesz
  dq  BSS_SIZE                  ; u64 p_memsz
  dq  PHDR_BSS.BSS_ALIGN        ; u64 p_align

assert (($-PHDR_BSS) = ELF64.PHEADER_ENTRY_SIZE)

TEXT:

  start: 

    ; Get dividend
  
    lea rdi, [prompt_1]
    call [printf]

    lea rdi, [scan_int]
    lea rsi, [dividend]
    call [scanf]
      
    ; Get divisor

    lea rdi, [prompt_2]
    call [printf]

    lea rdi, [scan_int]
    lea rsi, [divisor]
    call [scanf]

    ; dividend / divisor

    sub edx, edx
    mov eax, dword [dividend]
    div dword [divisor]

    mov ebp, eax
    mov ebx, edx

    ; print dividend / divisor

    lea rdi, [prompt_3]
    mov esi, dword [dividend]
    mov edx, dword [divisor]
    mov ecx, ebp
    call [printf]

    ; print dividend % divisor

    lea rdi, [prompt_4]
    mov esi, dword [dividend]
    mov edx, dword [divisor]
    mov ecx, ebx
    call [printf]

    call  [exit]
    
  align 8
  .RELOC:
    printf  dq ?
    scanf   dq ?
    exit    dq ?

  .DATA:
    prompt_1 db 'Enter dividend: ', 0
    prompt_2 db 'Enter divisor: ', 0
    scan_int db '%d', 0
    prompt_3 db '%d / %d = %d', 0x0a, 0
    prompt_4 db '%d %% %d = %d', 0x0a, 0

DYNAMIC: 
  .DT_NULL         =  0 ; ignored = Marks the end of the dynamic array
  .DT_NEEDED       =  1 ; d_val = The string table offset of the name of a needed library.
  .DT_PLTRELSZ     =  2 ; d_val = Total size, in bytes, of the relocation entries associated 
                        ;         with the procedure linkage table.
  .DT_PLTGOT       =  3 ; d_ptr = Contains an address associated with the linkage table. 
                        ;         The specific meaning of this field is processor-dependent.
  .DT_HASH         =  4 ; d_ptr = Address of the symbol hash table, described below.
  .DT_STRTAB       =  5 ; d_ptr = Address of the dynamic string table.
  .DT_SYMTAB       =  6 ; d_ptr = Address of the dynamic symbol table.
  .DT_RELA         =  7 ; d_ptr = Address of a relocation table with Elf64_Rela entries.
  .DT_RELASZ       =  8 ; d_val = Total size, in bytes, of the DT_RELA relocation table.
  .DT_RELAENT      =  9 ; d_val = Size, in bytes, of each DT_RELA relocation entry.
  .DT_STRSZ        = 10 ; d_val = Total size, in bytes, of the string table.
  .DT_SYMENT       = 11 ; d_val = Size, in bytes, of each symbol table entry.
  .DT_INIT         = 12 ; d_ptr = Address of the initialization function.
  .DT_FINI         = 13 ; d_ptr = Address of the termination function.
  .DT_SONAME       = 14 ; d_val = The string table offset of the name of this shared object.
  .DT_RPATH        = 15 ; d_val = The string table offset of a shared library search path string.
  .DT_SYMBOLIC     = 16 ; ignored = The presence of this dynamic table entry modifies the
                        ;           symbol resolution algorithm for references within the
                        ;           library. Symbols defined within the library are used to
                        ;           resolve references before the dynamic linker searches the
                        ;           usual search path.
  .DT_REL          = 17 ; d_ptr = Address of a relocation table with Elf64_Rel entries.
  .DT_RELSZ        = 18 ; d_val = Total size, in bytes, of the DT_REL relocation table.
  .DT_RELENT       = 19 ; d_val = Size, in bytes, of each DT_REL relocation entry.
  .DT_PLTREL       = 20 ; d_val = Type of relocation entry used for the procedure linkage
                        ;         table. The d_val member contains either DT_REL or DT_RELA.
  .DT_DEBUG        = 21 ; d_ptr = Reserved for debugger use.
  .DT_TEXTREL      = 22 ; ignored = The presence of this dynamic table entry signals that the
                        ;           relocation table contains relocations for a non-writable
                        ;           segment.
  .DT_JMPREL       = 23 ; d_ptr = Address of the relocations associated with the procedure
                        ;         linkage table.
  .DT_BIND_NOW     = 24 ; ignored = The presence of this dynamic table entry signals that the
                        ;           dynamic loader should process all relocations for this object
                        ;           before transferring control to the program.
  .DT_INIT_ARRAY   = 25 ; d_ptr = Pointer to an array of pointers to initialization functions.
  .DT_FINI_ARRAY   = 26 ; d_ptr = Pointer to an array of pointers to termination functions.
  .DT_INIT_ARRAYSZ = 27 ; d_val = Size, in bytes, of the array of initialization functions.
  .DT_FINI_ARRAYSZ = 28 ; d_val = Size, in bytes, of the array of termination functions.
  .DT_LOOS         = 0x60000000 ; Defines a range of dynamic table tags that are reserved for
  .DT_HIOS         = 0x6FFFFFFF ; environment-specific use
  .DT_LOPROC       = 0x70000000 ; Defines a range of dynamic table tags that are reserved for
  .DT_HIPROC       = 0x7FFFFFFF ; processor-specific use.

  ;  Dynamic section at offset 0x550 contains 8 entries:
  ;    Tag        Type                         Name/Value
  ;   0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
  ;   0x0000000000000005 (STRTAB)             0x4005e0
  ;   0x0000000000000006 (SYMTAB)             0x4005f4
  ;   0x000000000000000a (STRSZ)              18 (bytes)
  ;   0x000000000000000b (SYMENT)             24 (bytes)
  ;   0x0000000000000007 (RELA)               0x400628
  ;   0x0000000000000008 (RELASZ)             24 (bytes)
  ;   0x0000000000000009 (RELAENT)            24 (bytes)

  dq DYNAMIC.DT_NEEDED,  STRTAB.libc
  dq DYNAMIC.DT_STRTAB,  STRTAB
  dq DYNAMIC.DT_SYMTAB,  SYMTAB
  dq DYNAMIC.DT_STRSZ,   STRTAB.SIZE
  dq DYNAMIC.DT_SYMENT,  24
  dq DYNAMIC.DT_RELA,    RELA
  dq DYNAMIC.DT_RELASZ,  RELA.SIZE
  dq DYNAMIC.DT_RELAENT, 24
  dq DYNAMIC.DT_NULL,    0

  .SIZE=$-DYNAMIC 

STRTAB: 
  ; String table sections hold null-terminated character sequences, commonly called strings. 
  ; The object file uses these strings to represent symbol and section names. One references
  ; a string as an index into the string table section. The first byte, which is index zero,
  ; is defined to hold a null character. Likewise, a string table's last byte is defined to
  ; hold a null character, ensuring null termination for all strings. A string whose index 
  ; is zero specifies either no name or a null name, depending on the context. An empty 
  ; string table section is permitted; its section header's sh_size member would contain 
  ; zero. Non-zero indexes are invalid for an empty string table.

  .null=$-STRTAB 
    db 0 

  .libc=$-STRTAB 
    db "libc.so.6", 0 

  .printf=$-STRTAB 
     db "printf", 0 

  .scanf=$-STRTAB 
     db "scanf", 0 

  .exit=$-STRTAB 
     db "exit", 0 

  .SIZE=$-STRTAB 

align 4 
SYMTAB: 
  ; An object file's symbol table holds information needed to locate and relocate a 
  ; program's symbolic definitions and references. A symbol table index is a subscript
  ; into this array. Index 0 both designates the first entry in the table and serves 
  ; as the undefined symbol index. 
  ;
  ; The symbol table entry for index 0 (STN_UNDEF) is reserved; it holds the following.
  ; 
  ; Name      Value      Note
  ; st_name   0          No name
  ; st_value  0          Zero value
  ; st_size   0          No size
  ; st_info   0          No type, local binding
  ; st_other  0          Default visibility
  ; st_shndx  SHN_UNDEF  No section
  ;
  ; st_value
  ;   This member gives the value of the associated symbol. Depending on the context, this may be an absolute
  ;   value, an address, and so on; details appear below.
  ; st_size
  ;   Many symbols have associated sizes. For example, a data object's size is the number of bytes contained 
  ;   in the object. This member holds 0 if the symbol has no size or an unknown size.
  ; st_info
  ;   This member specifies the symbol's type and binding attributes. A list of the values and meanings appears below. 
  ;   The following code shows how to manipulate the values for both 32 and 64-bit objects.
  ;      #define ELF64_ST_BIND(i)   ((i)>>4)
  ;      #define ELF64_ST_TYPE(i)   ((i)&0xf)
  ;      #define ELF64_ST_INFO(b,t) (((b)<<4)+((t)&0xf))
  ; st_name
  ;   This member holds an index into the object file's symbol string table, which holds the character representations 
  ;   of the symbol names. If the value is non-zero, it represents a string table index that gives the symbol name. 
  ;   Otherwise, the symbol table entry has no name.
  ; st_other
  ;   This member currently specifies a symbol's visibility. A list of the values and meanings appears below. The following 
  ;   code shows how to manipulate the values for both 32 and 64-bit objects. Other bits contain 0 and have no defined meaning.
  ;      #define ELF32_ST_VISIBILITY(o) ((o)&0x3)
  ;      #define ELF64_ST_VISIBILITY(o) ((o)&0x3)
  ; st_shndx
  ;   Every symbol table entry is defined in relation to some section. This member holds the relevant section header table 
  ;   index. As the sh_link and sh_info interpretation table and the related text describe, some section indexes indicate 
  ;   special meanings.  If this member contains SHN_XINDEX, then the actual section header index is too large to fit in this
  ;   field. The actual value is contained in the associated section of type SHT_SYMTAB_SHNDX.

  ; A symbol's binding determines the linkage visibility and behavior.

  .STB_LOCAL  = 0   ; Local symbols are not visible outside the object file containing their definition. 
                    ; Local symbols of the same name may exist in multiple files without interfering with each other.
  .STB_GLOBAL = 1   ; Global symbols are visible to all object files being combined. One file's definition of a 
                    ; global symbol will satisfy another file's undefined reference to the same global symbol.
  .STB_WEAK   = 2   ; Weak symbols resemble global symbols, but their definitions have lower precedence.
  .STB_LOOS   = 10  ; Values in this inclusive range are reserved for operating system-specific semantics.
  .STB_HIOS   = 12  ;
  .STB_LOPROC = 13  ; Values in this inclusive range are reserved for processor-specific semantics. 
  .STB_HIPROC = 15  ; If meanings are specified, the processor supplement explains them.

  ; Symbol Types

  .STT_NOTYPE  = 0   ; The symbol's type is not specified.
  .STT_OBJECT  = 1   ; The symbol is associated with a data object, such as a variable, an array, and so on.
  .STT_FUNC    = 2   ; The symbol is associated with a function or other executable code.
  .STT_SECTION = 3   ; The symbol is associated with a section. Symbol table entries of this type exist 
                     ; primarily for relocation and normally have STB_LOCAL binding.
  .STT_FILE    = 4   ; Conventionally, the symbol's name gives the name of the source file associated with the
                     ; object file. A file symbol has STB_LOCAL binding, its section index is SHN_ABS, and it 
                     ; precedes the other STB_LOCAL symbols for the file, if it is present.
  .STT_COMMON  = 5   ; The symbol labels an uninitialized common block.
  .STT_TLS     = 6   ; The symbol specifies a Thread-Local Storage entity. When defined, it gives the assigned offset 
                     ; for the symbol, not the actual address. Symbols of type STT_TLS can be referenced by only special 
                     ; thread-local storage relocations and thread-local storage relocations can only reference symbols 
                     ; with type STT_TLS. Implementation need not support thread-local storage.
  .STT_LOOS    = 10  ; Values in this inclusive range are reserved for operating system-specific semantics.
  .STT_HIOS    = 12  ;
  .STT_LOPROC  = 13  ; Values in this inclusive range are reserved for processor-specific semantics. 
  .STT_HIPROC  = 15  ; If meanings are specified, the processor supplement explains them.

  ; Function symbols (those with type STT_FUNC) in shared object files have special significance. When another object file 
  ; references a function from a shared object, the link editor automatically creates a procedure linkage table entry for the 
  ; referenced symbol. Shared object symbols with types other than STT_FUNC will not be referenced automatically through the 
  ; procedure linkage table.

  .STN_UNDEF=($-SYMTAB)/24 
    dd 0 ; u32 st_name   = 0 
    db 0 ; u8  st_info   = 0
    db 0 ; u8  st_other  = 0
    dw 0 ; u16 st_shndx  = SHN_UNDEF
    dq 0 ; u64 st_value  = 0
    dq 0 ; u64 st_size   = 0

  .printf=($-SYMTAB)/24 
    dd STRTAB.printf                              ; u32 st_name
    db SYMTAB.STB_GLOBAL shl 4 + SYMTAB.STT_FUNC  ; u8  st_info
    db 0                                          ; u8  st_other
    dw 0                                          ; u16 st_shndx
    dq 0                                          ; u64 st_value
    dq 0                                          ; u64 st_size

  .scanf=($-SYMTAB)/24 
    dd STRTAB.scanf                               ; u32 st_name
    db SYMTAB.STB_GLOBAL shl 4 + SYMTAB.STT_FUNC  ; u8  st_info
    db 0                                          ; u8  st_other
    dw 0                                          ; u16 st_shndx
    dq 0                                          ; u64 st_value
    dq 0                                          ; u64 st_size

  .exit=($-SYMTAB)/24 
    dd STRTAB.exit                                ; u32 st_name
    db SYMTAB.STB_GLOBAL shl 4 + SYMTAB.STT_FUNC  ; u8  st_info
    db 0                                          ; u8  st_other
    dw 0                                          ; u16 st_shndx
    dq 0                                          ; u64 st_value
    dq 0                                          ; u64 st_size
  
  .SIZE=$-SYMTAB 

align 8 
RELA: 
  .R_AMD64_64 = 1 

  .printf: 
    dq printf                                  ; reloc addess 
    dq SYMTAB.printf shl 32 + RELA.R_AMD64_64  ; symtab_index shl 32 + type 
    dq 0                                       ; addend 

  .scanf: 
    dq scanf                                  ; reloc addess 
    dq SYMTAB.scanf shl 32 + RELA.R_AMD64_64  ; symtab_index shl 32 + type 
    dq 0                                      ; addend 

  .exit: 
    dq exit                                  ; reloc addess 
    dq SYMTAB.exit shl 32 + RELA.R_AMD64_64  ; symtab_index shl 32 + type 
    dq 0                                     ; addend 

  .SIZE=$-RELA 

INTERP:
  db "/lib64/ld-linux-x86-64.so.2", 0 ; Null-terminated pathname to invoke as interpreter.
  .SIZE=$-INTERP

FILE.SIZE=$-$$

org $$ + PHDR_BSS.BSS_OFFSET 
BSS:
  dividend rb 4
  divisor  rb 4
