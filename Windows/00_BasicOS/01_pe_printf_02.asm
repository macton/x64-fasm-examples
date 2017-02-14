; 01_pe_printf_02.asm
;   Print call return address; demonstrate call offsets rsp by 8 bytes

format binary as "exe" 
org 0 
use64 

SECTION_ALIGNMENT  = 0x00001000
FILE_ALIGNMENT     = 0x00000200
IMAGE_BASE         = 0x0000000000400000
STACK_RESERVE_SIZE = 0x0000000000001000
STACK_COMMIT_SIZE  = 0x0000000000001000
HEAP_RESERVE_SIZE  = 0x0000000000010000
HEAP_COMMIT_SIZE   = 0x0000000000000000
CODE_BASE          = CODE.RVA

macro align_section
{
  db (((($+(FILE_ALIGNMENT-1))/FILE_ALIGNMENT)*FILE_ALIGNMENT)-$) dup (0)
}

IMAGE_DOS_HEADER:

  db 0x4d, 0x5a             ; u16 e_magic
  db 0x80, 0x00             ; u16 e_cblp
  db 0x01, 0x00             ; u16 e_cp
  db 0x00, 0x00             ; u16 e_crlc
  db 0x04, 0x00             ; u16 e_cparhdr
  db 0x10, 0x00             ; u16 e_ss
  db 0xff, 0xff             ; u16 e_maxalloc
  db 0x00, 0x00             ; u16 e_minalloc
  db 0x40, 0x01             ; u16 e_sp 
  db 0x00, 0x00             ; u16 e_csum              
  db 0x00, 0x00             ; u16 e_ip  
  db 0x00, 0x00             ; u16 e_cs   
  db 0x40, 0x00             ; u16 e_lfarlc
  db 0x00, 0x00             ; u16 e_ovno              
  db 0x00, 0x00             ; u16 e_res[0]
  db 0x00, 0x00             ; u16 e_res[1]            
  db 0x00, 0x00             ; u16 e_res[2]
  db 0x00, 0x00             ; u16 e_res[3]            
  db 0x00, 0x00             ; u16 e_oemid 
  db 0x00, 0x00             ; u16 e_oeminfo
  db 0x00, 0x00             ; u16 e_res2[0]
  db 0x00, 0x00             ; u16 e_res2[1]
  db 0x00, 0x00             ; u16 e_res2[2]
  db 0x00, 0x00             ; u16 e_res2[3]           
  db 0x00, 0x00             ; u16 e_res2[4]
  db 0x00, 0x00             ; u16 e_res2[5]           
  db 0x00, 0x00             ; u16 e_res2[6]
  db 0x00, 0x00             ; u16 e_res2[7]          
  db 0x00, 0x00             ; u16 e_res2[8]
  db 0x00, 0x00             ; u16 e_res2[9]
  dd IMAGE_NT_HEADERS       ; u32 e_lfanew

IMAGE_DOS_HEADER_END:
IMAGE_DOS_HEADER_SIZE = IMAGE_DOS_HEADER_END - IMAGE_DOS_HEADER
assert (IMAGE_DOS_HEADER_SIZE = 0x40)

IMAGE_DOS_PROGRAM:

  db 0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd 
  db 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68
  db 0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72 
  db 0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f 
  db 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e 
  db 0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20 
  db 0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x0d, 0x0a, 0x24
  db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 

IMAGE_DOS_PROGRAM_END:
IMAGE_DOS_PROGRAM_SIZE = IMAGE_DOS_PROGRAM_END - IMAGE_DOS_PROGRAM

IMAGE_NT_HEADERS: 

  db 0x50, 0x45, 0x00, 0x00 ; u32 Signature 

IMAGE_FILE_HEADER:

  db 0x64, 0x86                 ; u16 Machine
  dw SECTION_TABLE_ENTRY_COUNT  ; u16 NumberOfSections
  dd 0                          ; u32 TimeDateStamp
  dd 0                          ; u32 PointerToSymbolTable
  dd 0                          ; u32 NumberOfSymbols
  dw IMAGE_OPTIONAL_HEADER_SIZE ; u16 SizeOfOptionalHeader
  db 0x2f, 0x00                 ; u16 Characteristics

IMAGE_FILE_HEADER_END:
IMAGE_FILE_HEADER_SIZE = IMAGE_FILE_HEADER_END-IMAGE_FILE_HEADER
assert (IMAGE_FILE_HEADER_SIZE = 0x14)

IMAGE_OPTIONAL_HEADER:

  db 0x0b, 0x02                                     ; u16 Magic
  db 0x01                                           ; u8  MajorLinkerVersion
  db 0x47                                           ; u8  MinorLinkerVersion
  dd CODE_FILE_SIZE                                 ; u32 SizeOfCode
  dd 0                                              ; u32 SizeofInitializedData (unused)
  dd 0                                              ; u32 SizeOfUninitializedData (unused)
  dd start.RVA                                      ; u32 AddressOfEntryPoint
  dd CODE_BASE                                      ; u32 BaseOfCode
  dq IMAGE_BASE                                     ; u64 ImageBase
  dd SECTION_ALIGNMENT                              ; u32 SectionAlignment
  dd FILE_ALIGNMENT                                 ; u32 FileAlignment
  db 0x01, 0x00                                     ; u16 MajorOperatingSystemVersion
  db 0x00, 0x00                                     ; u16 MinorOperatingSystemVersion
  db 0x00, 0x00                                     ; u16 MajorImageVersion
  db 0x00, 0x00                                     ; u16 MinorImageVersion
  db 0x05, 0x00                                     ; u16 MajorSubsystemVersion
  db 0x00, 0x00                                     ; u16 MinorSubsystemVersion
  db 0x00, 0x00, 0x00, 0x00                         ; u32 Win32VersionValue
  dd IMAGE_SIZE                                     ; u32 SizeOfImage
  dd IMAGE_HEADERS_ROUND_SIZE                       ; u32 SizeOfHeaders
  dd 0                                              ; u32 Checksum
  db 0x03, 0x00                                     ; u16 Subsystem
  db 0x00, 0x00                                     ; u16 DllCharacteristics
  dq STACK_RESERVE_SIZE                             ; u64 SizeOfStackReserve
  dq STACK_COMMIT_SIZE                              ; u64 SizeOfStackCommit
  dq HEAP_RESERVE_SIZE                              ; u64 SizeOfHeapReserve
  dq HEAP_COMMIT_SIZE                               ; u64 SizeOfHeapCommit
  db 0x00, 0x00, 0x00, 0x00                         ; u32 LoaderFlags
  dd IMAGE_DATA_DIRECTORIES_COUNT                   ; u32 NumberOfRvaAndSizes

IMAGE_DATA_DIRECTORIES:

IMAGE_DIRECTORY_ENTRY_EXPORT:

  dd 0  ; u32 VirtualAddress
  dd 0  ; u32 Size

IMAGE_DIRECTORY_ENTRY_IMPORT:

  dd IDATA.RVA  ; u32 VirtualAddress
  dd IDATA_SIZE ; u32 Size

IMAGE_DIRECTORY_ENTRY_RESOURCE:

  dd 0  ; u32 VirtualAddress
  dd 0  ; u32 Size

IMAGE_DIRECTORY_ENTRY_EXCEPTION:

  dd 0  ; u32 VirtualAddress
  dd 0  ; u32 Size

IMAGE_DIRECTORY_ENTRY_SECURITY:

  dd 0  ; u32 VirtualAddress
  dd 0  ; u32 Size

IMAGE_DIRECTORY_ENTRY_BASERELOC:

  dd 0  ; u32 VirtualAddress
  dd 0  ; u32 Size

IMAGE_DIRECTORY_ENTRY_DEBUG:

  dd 0  ; u32 VirtualAddress
  dd 0  ; u32 Size

IMAGE_DIRECTORY_ENTRY_COPYRIGHT:

  dd 0  ; u32 VirtualAddress
  dd 0  ; u32 Size

IMAGE_DIRECTORY_ENTRY_GLOBALPTR:

  dd 0  ; u32 VirtualAddress
  dd 0  ; u32 Size

IMAGE_DIRECTORY_ENTRY_TLS:

  dd 0  ; u32 VirtualAddress
  dd 0  ; u32 Size

IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:

  dd 0  ; u32 VirtualAddress
  dd 0  ; u32 Size

IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:

  dd 0  ; u32 VirtualAddress
  dd 0  ; u32 Size

IMAGE_DIRECTORY_ENTRY_IAT:

  dd 0  ; u32 VirtualAddress
  dd 0  ; u32 Size

IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:

  dd 0  ; u32 VirtualAddress
  dd 0  ; u32 Size

IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:

  dd 0  ; u32 VirtualAddress
  dd 0  ; u32 Size

IMAGE_DIRECTORY_ENTRY_RESERVED:

  dd 0  ; u32 VirtualAddress
  dd 0  ; u32 Size

IMAGE_DATA_DIRECTORIES_END:
IMAGE_DATA_DIRECTORIES_COUNT = (IMAGE_DATA_DIRECTORIES_END-IMAGE_DATA_DIRECTORIES)/8

IMAGE_OPTIONAL_HEADER_END:
IMAGE_OPTIONAL_HEADER_SIZE = IMAGE_OPTIONAL_HEADER_END-IMAGE_OPTIONAL_HEADER
assert (IMAGE_OPTIONAL_HEADER_SIZE = 0xF0)

SECTION_TABLE:

SECTION_TABLE_ENTRY_CODE:

  db '.code',0,0,0                                  ; char Name[8]
  dd CODE_IMAGE_SIZE                                ; u32  VirtualSize
  dd CODE.RVA                                       ; u32  VirtualAddress
  dd CODE_FILE_SIZE                                 ; u32  SizeOfRawData
  dd CODE                                           ; u32  PointerToRawData
  dd 0                                              ; u32  PointerToRelocations
  dd 0                                              ; u32  PointerToLinenumbers
  dw 0                                              ; u16  NumberOfRelocations
  dw 0                                              ; u16  NumberOfLineNumbers
  db 0x20, 0x00, 0x00, 0x60                         ; u32  Characteristics

SECTION_TABLE_ENTRY_CODE_END:
SECTION_TABLE_ENTRY_CODE_SIZE = SECTION_TABLE_ENTRY_CODE_END - SECTION_TABLE_ENTRY_CODE
assert (SECTION_TABLE_ENTRY_CODE_SIZE = 0x28)

SECTION_TABLE_ENTRY_IDATA:

  db '.idata',0,0                                   ; char Name[8]
  dd IDATA_IMAGE_SIZE                               ; u32  VirtualSize
  dd IDATA.RVA                                      ; u32  VirtualAddress
  dd IDATA_FILE_SIZE                                ; u32  SizeOfRawData
  dd IDATA                                          ; u32  PointerToRawData
  dd 0                                              ; u32  PointerToRelocations
  dd 0                                              ; u32  PointerToLinenumbers
  dw 0                                              ; u16  NumberOfRelocations
  dw 0                                              ; u16  NumberOfLineNumbers
  db 0x40, 0x00, 0x00, 0xc0                         ; u32  Characteristics

SECTION_TABLE_ENTRY_IDATA_END:
SECTION_TABLE_ENTRY_IDATA_SIZE = SECTION_TABLE_ENTRY_IDATA_END - SECTION_TABLE_ENTRY_IDATA
assert (SECTION_TABLE_ENTRY_IDATA_SIZE = 0x28)

SECTION_TABLE_END:
SECTION_TABLE_SIZE = SECTION_TABLE_END-SECTION_TABLE

SECTION_TABLE_ENTRY_COUNT = ((SECTION_TABLE_END-SECTION_TABLE) / 0x28)

IMAGE_NT_HEADERS_END:
IMAGE_NT_HEADERS_SIZE = IMAGE_NT_HEADERS_END-IMAGE_NT_HEADERS

IMAGE_NT_HEADERS_PADDING:
  align_section

IMAGE_NT_HEADERS_PADDING_END:
IMAGE_HEADERS_ROUND_SIZE = IMAGE_NT_HEADERS_PADDING_END-IMAGE_DOS_HEADER

HEADER_SECTION_END:
HEADER_IMAGE_SIZE = (((HEADER_SECTION_END-IMAGE_DOS_HEADER)+(SECTION_ALIGNMENT-1))/SECTION_ALIGNMENT)*SECTION_ALIGNMENT

CODE:
CODE.RVA = HEADER_IMAGE_SIZE

; int start(void)
;   Demonstrate via print that call pushes address on to stack (misaligning by 8bytes, as expected)
;     - Retreive the return address from the stack
;     - Compare to the expected return address 
start:
start.RVA = (start-CODE)+CODE.RVA

  ; Calling convention requires 16 byte alignment; call to this point (and each call) shifts by 8, so fix up (i.e. was 0x20, now 0x28)
  sub    rsp,0x28

  call foo

  mov    eax,0x2a
  mov    ecx,eax
  call qword [ rip + (ExitProcess-((@f-CODE)+CODE.RVA))  ] 
  @@:

  add    rsp,0x28

  ; void bar(void)
  bar:
    sub rsp, 0x28

    ; print rsp 
    lea rcx, [print_3]
    mov rdx, rsp
    call qword [ rip + (printf-((@f-CODE)+CODE.RVA))  ] 
    @@:
  
    ; print return address from caller (pushed from call instruction)
    lea rcx, [print_1]
    mov rdx, [rsp+0x28]
    call qword [ rip + (printf-((@f-CODE)+CODE.RVA))  ] 
    @@:
  
    ; print actual known address after call location
    lea rcx, [print_2]
    mov rdx, IMAGE_BASE + (foo.return_addr-CODE)+CODE.RVA
    call qword [ rip + (printf-((@f-CODE)+CODE.RVA))  ] 
    @@:

    mov rcx, [rsp+0x28]
    mov rdx, IMAGE_BASE + (foo.return_addr-CODE)+CODE.RVA
    cmp rcx, rdx

    lea rcx, [print_OK]
    je .print_result
      lea rcx, [print_FAIL]

    .print_result: 
      call qword [ rip + (printf-((@f-CODE)+CODE.RVA))  ] 
      @@:
  
    add rsp, 0x28
    ret
  
  ; void foo(void)
  foo:
    sub rsp, 0x28
  
    call bar
    .return_addr:
  
    add rsp, 0x28
    ret

  ; DATA
  print_1    db 'Return address          = 0x%p',0x0a,0
  print_2    db 'Expected return address = 0x%p',0x0a,0
  print_3    db 'rsp (in bar)            = 0x%p',0x0a,0
  print_OK   db 'OK!',0x0a,0
  print_FAIL db 'FAILED!',0x0a,0

CODE_END:
CODE_SIZE = CODE_END-CODE

CODE_PADDING:
  align_section

CODE_FILE_END:
CODE_FILE_SIZE = (((CODE_FILE_END-CODE)+(FILE_ALIGNMENT-1))/FILE_ALIGNMENT)*FILE_ALIGNMENT

CODE_SECTION_END:
CODE_IMAGE_SIZE = (((CODE_SECTION_END-CODE)+(SECTION_ALIGNMENT-1))/SECTION_ALIGNMENT)*SECTION_ALIGNMENT

IDATA:
IDATA.RVA = CODE.RVA + CODE_IMAGE_SIZE

IMAGE_IMPORT_DIRECTORY:
IMAGE_IMPORT_DIRECTORY.RVA = (IMAGE_IMPORT_DIRECTORY-IDATA)+IDATA.RVA

IMAGE_IMPORT_KERNEL32:

  dd KERNEL32_IMPORT_LOOKUP_TABLE.RVA  ; u32 rvaImportLookupTable
  dd 0                                 ; u32 TimeDateStamp
  dd 0                                 ; u32 ForwarderChain
  dd KERNEL32_MODULE_NAME.RVA          ; u32 rvaModuleName
  dd KERNEL32_IMPORT_ADDRESS_TABLE.RVA ; u32 rvaImportAddressTable

IMAGE_IMPORT_MSVCRT:

  dd MSVCRT_IMPORT_LOOKUP_TABLE.RVA    ; u32 rvaImportLookupTable
  dd 0                                 ; u32 TimeDateStamp
  dd 0                                 ; u32 ForwarderChain
  dd MSVCRT_MODULE_NAME.RVA            ; u32 rvaModuleName
  dd MSVCRT_IMPORT_ADDRESS_TABLE.RVA   ; u32 rvaImportAddressTable

IMAGE_IMPORT_END:

  dd 0 ; u32 rvaImportLookupTable
  dd 0 ; u32 TimeDateStamp
  dd 0 ; u32 ForwarderChain
  dd 0 ; u32 rvaModuleName
  dd 0 ; u32 rvaImportAddressTable

IMAGE_IMPORT_DIRECTORY_END:
IMAGE_IMPORT_DIRECTORY_SIZE = IMAGE_IMPORT_DIRECTORY_END-IMAGE_IMPORT_DIRECTORY

KERNEL32_MODULE_NAME:
KERNEL32_MODULE_NAME.RVA =  (KERNEL32_MODULE_NAME-IDATA)+IDATA.RVA

  db 'kernel32.dll', 0

MSVCRT_MODULE_NAME:
MSVCRT_MODULE_NAME.RVA =  (MSVCRT_MODULE_NAME-IDATA)+IDATA.RVA

  db 'msvcrt.dll', 0

MODULE_NAME_PADDING:
  align 8

KERNEL32_IMPORT_LOOKUP_TABLE:
KERNEL32_IMPORT_LOOKUP_TABLE.RVA = (KERNEL32_IMPORT_LOOKUP_TABLE-IDATA)+IDATA.RVA

  dq IMPORT_NAMES.ExitProcess.RVA
  dq 0 ; END

KERNEL32_IMPORT_ADDRESS_TABLE:
KERNEL32_IMPORT_ADDRESS_TABLE.RVA = (KERNEL32_IMPORT_ADDRESS_TABLE-IDATA)+IDATA.RVA

  ExitProcess = ($-IDATA)+IDATA.RVA ; RVA
  dq IMPORT_NAMES.ExitProcess.RVA
  dq 0 ; END

MSVCRT_IMPORT_LOOKUP_TABLE:
MSVCRT_IMPORT_LOOKUP_TABLE.RVA = (MSVCRT_IMPORT_LOOKUP_TABLE-IDATA)+IDATA.RVA

  dq IMPORT_NAMES.printf.RVA
  dq 0 ; END

MSVCRT_IMPORT_ADDRESS_TABLE:
MSVCRT_IMPORT_ADDRESS_TABLE.RVA = (MSVCRT_IMPORT_ADDRESS_TABLE-IDATA)+IDATA.RVA

  printf = ($-IDATA)+IDATA.RVA ; RVA
  dq IMPORT_NAMES.printf.RVA
  dq 0 ; END

IMPORT_NAMES:

  ; kernel32.dll "ExitProcess"

  .ExitProcess:
  .ExitProcess.RVA = (IMPORT_NAMES.ExitProcess-IDATA)+IDATA.RVA

  dw 0                 ; u16     Hint
  db 'ExitProcess', 0  ; cstring Name

  ; msvcrt.dll "printf"

  .printf:
  .printf.RVA = (IMPORT_NAMES.printf-IDATA)+IDATA.RVA

  dw 0            ; u16     Hint
  db 'printf', 0  ; cstring Name

IMPORT_NAMES_END:

IMPORT_NAMES_PADDING:
  align 8

IDATA_END:
IDATA_SIZE = IDATA_END-IDATA

IDATA_PADDING:
  align_section

IDATA_FILE_END:
IDATA_FILE_SIZE = (((IDATA_FILE_END-IDATA)+(FILE_ALIGNMENT-1))/FILE_ALIGNMENT)*FILE_ALIGNMENT

IDATA_SECTION_END:
IDATA_IMAGE_SIZE = (((IDATA_SECTION_END-IDATA)+(SECTION_ALIGNMENT-1))/SECTION_ALIGNMENT)*SECTION_ALIGNMENT

; SizeOfImage = Sum of sizes of all in-memory sections (aligned)
; Here, IDATA is the last section
IMAGE_SIZE = IDATA.RVA + (((IDATA_SIZE+(SECTION_ALIGNMENT-1))/SECTION_ALIGNMENT)*SECTION_ALIGNMENT)

FILE_END:
FILE_SIZE = FILE_END-IMAGE_DOS_HEADER
