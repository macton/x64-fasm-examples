; See: 
;   - https://board.flatassembler.net/topic.php?p=179318
;   - http://win32assembly.programminghorizon.com/pe-tut1.html
;   - https://www.instapaper.com/text?u=http%3A%2F%2Fwww.phreedom.org%2Fresearch%2Ftinype%2F
;   - https://msdn.microsoft.com/en-us/library/ms809762.aspx

format binary as "exe" 

org 0 
use64 

PE_HEADER:
  ; PE Headers are aliased as follows:
  ;
  ;  IMAGE_DOS_HEADER:
  ;    u16 e_magic
  ;    u16 e_cblp
  ;    u16 e_cp
  ;    u16 e_crlc
  ;    u16 e_cparhdr
  ;    u16 e_minalloc
  ;    u16 e_maxalloc
  ;    u16 e_ss
  ;                         IMAGE_NT_HEADERS:
  ;    u16 e_sp                u32 Signature 
  ;    u16 e_csum              
  ;                         IMAGE_FILE_HEADER:
  ;    u16 e_ip                u16 Machine
  ;    u16 e_cs                u16 NumberOfSections
  ;    u16 e_lfarlc            u32 TimeDateStamp
  ;    u16 e_ovno              
  ;    u16 e_res[0]            u32 PointerToSymbolTable
  ;    u16 e_res[1]            
  ;    u16 e_res[2]            u32 NumberOfSymbols
  ;    u16 e_res[3]            
  ;    u16 e_oemid             u16 SizeOfOptionalHeader
  ;    u16 e_oeminfo           u16 Characteristics
  ;
  ;                         IMAGE_OPTIONAL_HEADER:
  ;    u16 e_res2[0]           u16 Magic
  ;    u16 e_res2[1]           u8  MajorLinkerVersion
  ;                            u8  MinorLinkerVersion
  ;    u16 e_res2[2]           u32 SizeOfCode
  ;    u16 e_res2[3]           
  ;    u16 e_res2[4]           u32 SizeOfInitializedData
  ;    u16 e_res2[5]           
  ;    u16 e_res2[6]           u32 SizeOfUninitializedData
  ;    u16 e_res2[7]          
  ;    u16 e_res2[8]           u32 AddressOfEntryPoint
  ;    u16 e_res2[9]
  ;    u32 e_lfanew            u32 BaseOfCode
  ;                            u64 ImageBase
  ;                            u32 SectionAlignment
  ;                            u32 FileAlignment
  ;                            u16 MajorOperatingSystemVersion
  ;                            u16 MinorOperatingSystemVersion
  ;                            u16 MajorImageVersion
  ;                            u16 MinorImageVersion
  ;                            u16 MajorSubsystemVersion
  ;                            u16 MinorSubsystemVersion
  ;                            u32 Win32VersionValue
  ;                            u32 SizeOfImage
  ;                            u32 SizeOfHeaders
  ;                            u32 Checksum
  ;                            u16 Subsystem
  ;                            u16 DllCharacteristics
  ;                            u64 SizeOfStackReserve
  ;                            u64 SizeOfStackCommit
  ;                            u64 SizeOfHeapReserve
  ;                            u64 SizeOfHeapCommit
  ;                            u32 LoaderFlags
  ;                            u32 NumberOfRvaAndSizes
  ;                            IMAGE_DATA_DIRECTORY DataDirectory[2];
  
  ; Nothing aliasing the IMAGE_DOS_HEADER matters (don't care if DOS stub actually works), except e_lfanew 
  ; So:
  ;    u32 e_lfanew == u32 BaseOfCode
  ;    -> Both point to the top of IMAGE_NT_HEADERS at offset 0x10
  
IMAGE_DOS_HEADER:
  db "MZ" ;    u16 e_magic
  dw 0    ;    u16 e_cblp
  dw 0    ;    u16 e_cp
  dw 0    ;    u16 e_crlc
  dw 0    ;    u16 e_cparhdr
  dw 0    ;    u16 e_minalloc
  dw 0    ;    u16 e_maxalloc
  dw 0    ;    u16 e_ss

IMAGE_NT_HEADERS:
  db "PE", 0, 0 ;    u32 Signature 

IMAGE_FILE_HEADER:
  ; Machine
  .IMAGE_FILE_MACHINE_AMD64 = 0x8664

  ; Characteristics
  .IMAGE_FILE_RELOCS_STRIPPED         = 0x0001 
  .IMAGE_FILE_EXECUTABLE_IMAGE        = 0x0002
  .IMAGE_FILE_LINE_NUMS_STRIPPED      = 0x0004
  .IMAGE_FILE_LOCAL_SYMS_STRIPPED     = 0x0008
  .IMAGE_FILE_AGGRESIVE_WS_TRIM       = 0x0010
  .IMAGE_FILE_LARGE_ADDRESS_AWARE     = 0x0020
  .IMAGE_FILE_16BIT_MACHINE           = 0x0040
  .IMAGE_FILE_BYTES_REVERSED_LO       = 0x0080
  .IMAGE_FILE_32BIT_MACHINE           = 0x0100
  .IMAGE_FILE_DEBUG_STRIPPED          = 0x0200
  .IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400
  .IMAGE_FILE_NET_RUN_FROM_SWAP       = 0x0800
  .IMAGE_FILE_SYSTEM                  = 0x1000
  .IMAGE_FILE_DLL                     = 0x2000
  .IMAGE_FILE_UP_SYSTEM_ONLY          = 0x4000
  .IMAGE_FILE_BYTES_REVERSED_HI       = 0x8000

  dw .IMAGE_FILE_MACHINE_AMD64  ; u16 Machine
  dw 1                          ; u16 NumberOfSections
  dd 0                          ; u32 TimeDateStamp
  dd 0                          ; u32 PointerToSymbolTable
  dd 0                          ; u32 NumberOfSymbols
  dw IMAGE_OPTIONAL_HEADER.SIZE ; u16 SizeOfOptionalHeader
  dw .IMAGE_FILE_LARGE_ADDRESS_AWARE + .IMAGE_FILE_RELOCS_STRIPPED + .IMAGE_FILE_EXECUTABLE_IMAGE ; u16 Characteristics

IMAGE_OPTIONAL_HEADER:
  ; Magic
  .MAGIC = 0x020B

  ; Subsystem
  .IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
  .IMAGE_SUBSYSTEM_WINDOWS_CUI = 3

  dw .MAGIC                       ; u16 Magic
  db 0                            ; u8  MajorLinkerVersion
  db 0                            ; u8  MinorLinkerVersion
  dd 0                            ; u32 SizeOfCode
  dd 0                            ; u32 SizeOfInitializedData
  dd 0                            ; u32 SizeOfUninitializedData
  dd start                        ; u32 AddressOfEntryPoint
  dd IMAGE_NT_HEADERS             ; u32 BaseOfCode
  dq 0x140000000                  ; u64 ImageBase
  dd 0x10                         ; u32 SectionAlignment
  dd 0x10                         ; u32 FileAlignment
  dw 1                            ; u16 MajorOperatingSystemVersion
  dw 0                            ; u16 MinorOperatingSystemVersion
  dw 0                            ; u16 MajorImageVersion
  dw 0                            ; u16 MinorImageVersion
  dw 6                            ; u16 MajorSubsystemVersion
  dw 0                            ; u16 MinorSubsystemVersion
  dd 0                            ; u32 Win32VersionValue
  dd FILE.SIZE                    ; u32 SizeOfImage
  dd PE_HEADER.SIZE               ; u32 SizeOfHeaders
  dd 0                            ; u32 Checksum
  dw .IMAGE_SUBSYSTEM_WINDOWS_GUI ; u16 Subsystem
  dw 0                            ; u16 DllCharacteristics
  dq 0x100000                     ; u64 SizeOfStackReserve
  dq 0x1000                       ; u64 SizeOfStackCommit
  dq 0x100000                     ; u64 SizeOfHeapReserve
  dq 0x1000                       ; u64 SizeOfHeapCommit
  dd 0                            ; u32 LoaderFlags
  dd 2                            ; u32 NumberOfRvaAndSizes

; IMAGE_DATA_DIRECTORY DataDirectory[2];
; DataDirectory is in a fixed order.

IMAGE_DIRECTORY_ENTRY_EXPORT:
  dd 0 ; u32 VirtualAddress
  dd 0 ; u32 Size

IMAGE_DIRECTORY_ENTRY_IMPORT:
  dd IMPORT_TABLE       ; u32 VirtualAddress
  dd IMPORT_TABLE.SIZE  ; u32 Size

IMAGE_OPTIONAL_HEADER.SIZE = $-IMAGE_OPTIONAL_HEADER

SECTION_TABLE:
  ; Characteristics
  .IMAGE_SCN_TYPE_REG                  = 0x00000000
  .IMAGE_SCN_TYPE_DSECT                = 0x00000001
  .IMAGE_SCN_TYPE_NOLOAD               = 0x00000002
  .IMAGE_SCN_TYPE_GROUP                = 0x00000004
  .IMAGE_SCN_TYPE_NO_PAD               = 0x00000008
  .IMAGE_SCN_TYPE_COPY                 = 0x00000010
  .IMAGE_SCN_CNT_CODE                  = 0x00000020
  .IMAGE_SCN_CNT_INITIALIZED_DATA      = 0x00000040
  .IMAGE_SCN_CNT_UNINITIALIZED_DATA    = 0x00000080
  .IMAGE_SCN_LNK_OTHER                 = 0x00000100
  .IMAGE_SCN_LNK_INFO                  = 0x00000200
  .IMAGE_SCN_TYPE_OVER                 = 0x00000400
  .IMAGE_SCN_LNK_REMOVE                = 0x00000800
  .IMAGE_SCN_LNK_COMDAT                = 0x00001000
  .IMAGE_SCN_MEM_PROTECTED             = 0x00004000
  .IMAGE_SCN_MEM_FARDATA               = 0x00008000
  .IMAGE_SCN_MEM_SYSHEAP               = 0x00010000
  .IMAGE_SCN_MEM_PURGEABLE             = 0x00020000
  .IMAGE_SCN_MEM_16BIT                 = 0x00020000
  .IMAGE_SCN_MEM_LOCKED                = 0x00040000
  .IMAGE_SCN_MEM_PRELOAD               = 0x00080000
  .IMAGE_SCN_ALIGN_1BYTES              = 0x00100000
  .IMAGE_SCN_ALIGN_2BYTES              = 0x00200000
  .IMAGE_SCN_ALIGN_4BYTES              = 0x00300000
  .IMAGE_SCN_ALIGN_8BYTES              = 0x00400000
  .IMAGE_SCN_ALIGN_16BYTES             = 0x00500000
  .IMAGE_SCN_ALIGN_32BYTES             = 0x00600000
  .IMAGE_SCN_ALIGN_64BYTES             = 0x00700000
  .IMAGE_SCN_ALIGN_128BYTES            = 0x00800000
  .IMAGE_SCN_ALIGN_256BYTES            = 0x00900000
  .IMAGE_SCN_ALIGN_512BYTES            = 0x00A00000
  .IMAGE_SCN_ALIGN_1024BYTES           = 0x00B00000
  .IMAGE_SCN_ALIGN_2048BYTES           = 0x00C00000
  .IMAGE_SCN_ALIGN_4096BYTES           = 0x00D00000
  .IMAGE_SCN_ALIGN_8192BYTES           = 0x00E00000
  .IMAGE_SCN_ALIGN_MASK                = 0x00F00000
  .IMAGE_SCN_LNK_NRELOC_OVFL           = 0x01000000
  .IMAGE_SCN_MEM_DISCARDABLE           = 0x02000000
  .IMAGE_SCN_MEM_NOT_CACHED            = 0x04000000
  .IMAGE_SCN_MEM_NOT_PAGED             = 0x08000000
  .IMAGE_SCN_MEM_SHARED                = 0x10000000
  .IMAGE_SCN_MEM_EXECUTE               = 0x20000000
  .IMAGE_SCN_MEM_READ                  = 0x40000000
  .IMAGE_SCN_MEM_WRITE                 = 0x80000000

  ; Only one section '.text': includes code, data and import table.

  db '.text',0,0,0  ; char Name[8]
  dd TEXT.SIZE      ; u32  VirtualSize
  dd TEXT           ; u32  VirtualAddress
  dd TEXT.SIZE      ; u32  SizeOfRawData
  dd TEXT           ; u32  PointerToRawData
  dd 0              ; u32  PointerToRelocations
  dd 0              ; u32  PointerToLinenumbers
  dw 0              ; u16  NumberOfRelocations
  dw 0              ; u16  NumberOfLinenumbers
  dd .IMAGE_SCN_MEM_WRITE + .IMAGE_SCN_CNT_CODE ; u32  Characteristics

PE_HEADER.SIZE = $-PE_HEADER

TEXT:

  start: 
    sub rsp, 28h         ; space for 4 arguments + 16byte aligned stack 
    xor r9d, r9d         ; 4. argument: r9d = uType = 0 
    lea r8, [MsgCaption] ; 3. argument: r8  = caption 
    lea rdx,[MsgBoxText] ; 2. argument: edx = window text 
    xor ecx, ecx         ; 1. argument: rcx = hWnd = NULL 
    call [MessageBox] 
    call [ExitProcess] 
    add rsp, 28h 
    ret 
  
  MsgCaption db "01_hello_msgbox", 0 
  MsgBoxText db "Hello, World!",0 
  
IMPORT_TABLE:
  ; See: http://sandsprite.com/CodeStuff/Understanding_imports.html
  ; 
  ; IMAGE_IMPORT_DIRECTORY
  ;   dd rvaImportLookupTable   (not used)
  ;   dd TimeDateStamp          (not used)
  ;   dd ForwarderChain         (not used)
  ;   dd rvaModuleName          NULL-terminated ASCII string containing the imported DLL's name.
  ;   dd rvaImportAddressTable  Array of pointers to IMAGE_IMPORT_BY_NAME structures.
  ;                             Loader replaces those pointers with addresses to functions.
  ;                             Array terminated with NULL entry. 
 
IMPORT_KERNEL32_DLL:
  dd 0                       ; u32 rvaImportLookupTable
  dd 0                       ; u32 TimeDateStamp
  dd 0                       ; u32 ForwarderChain
  dd KERNEL32_MODULE_NAME    ; u32 rvaModuleName
  dd KERNEL32_ADDRESS_TABLE  ; u32 rvaImportAddressTable

IMPORT_USER32_DLL:
  dd 0                       ; u32 rvaImportLookupTable
  dd 0                       ; u32 TimeDateStamp
  dd 0                       ; u32 ForwarderChain
  dd USER32_MODULE_NAME      ; u32 rvaModuleName
  dd USER32_ADDRESS_TABLE    ; u32 rvaImportAddressTable

IMPORT_END:
  dd 0                       ; u32 rvaImportLookupTable
  dd 0                       ; u32 TimeDateStamp
  dd 0                       ; u32 ForwarderChain
  dd 0                       ; u32 rvaModuleName
  dd 0                       ; u32 rvaImportAddressTable

KERNEL32_ADDRESS_TABLE:
  ExitProcess dq IMPORT_NAMES.ExitProcess
  dq 0 ; NULL Terminator
 
USER32_ADDRESS_TABLE:
  MessageBox dq IMPORT_NAMES.MessageBox
  dq 0 ; NULL Terminator

KERNEL32_MODULE_NAME:
  db "kernel32", 0 

USER32_MODULE_NAME:
  db "user32", 0 

IMPORT_NAMES:
  .ExitProcess:
    dw 0               ; u16     Hint
    db "ExitProcess",0 ; cstring Name
  .MessageBox:
    dw 0               ; u16     Hint
    db "MessageBoxA",0 ; cstring Name

IMPORT_TABLE.SIZE = $-IMPORT_TABLE
TEXT.SIZE = $-TEXT

FILE.SIZE = $-IMAGE_DOS_HEADER
