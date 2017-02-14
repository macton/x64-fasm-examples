; 00_return_04.asm
;   1. Disassemble code at start

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

macro print_value_x32 description, value
{
  bits = 32
  display description
  display '0x'
  repeat bits/4
    d = '0' + value shr (bits-%*4) and 0Fh
    if d > '9'
      d = d + 'A'-'9'-1
    end if
    display d
  end repeat
  display $a
}

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
print_value_x32 "IMAGE_DOS_PROGRAM_SIZE            = ", IMAGE_DOS_PROGRAM_SIZE

IMAGE_NT_HEADERS: 
print_value_x32 "IMAGE_NT_HEADERS                  = ", IMAGE_NT_HEADERS

  db 0x50, 0x45, 0x00, 0x00 ; u32 Signature 

IMAGE_FILE_HEADER:
print_value_x32 "IMAGE_FILE_HEADER                 = ", IMAGE_FILE_HEADER

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
print_value_x32 "IMAGE_OPTIONAL_HEADER             = ", IMAGE_OPTIONAL_HEADER

  db 0x0b, 0x02                                     ; u16 Magic
  db 0x01                                           ; u8  MajorLinkerVersion
  db 0x47                                           ; u8  MinorLinkerVersion
  dd CODE_FILE_SIZE                                 ; u32 SizeOfCode
  dd 0                                              ; u32 SizeofInitializedData (unused)
  dd 0                                              ; u32 SizeOfUninitializedData (unused)
  dd start.RVA                                      ; u32 AddressOfEntryPoint
  dd CODE.RVA                                       ; u32 BaseOfCode
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
print_value_x32 "SECTION_TABLE                     = ", SECTION_TABLE

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
print_value_x32 "SECTION_TABLE_SIZE                = ", SECTION_TABLE_SIZE

SECTION_TABLE_ENTRY_COUNT = ((SECTION_TABLE_END-SECTION_TABLE) / 0x28)

IMAGE_NT_HEADERS_END:
IMAGE_NT_HEADERS_SIZE = IMAGE_NT_HEADERS_END-IMAGE_NT_HEADERS

IMAGE_NT_HEADERS_PADDING:
  align_section

IMAGE_NT_HEADERS_PADDING_END:
IMAGE_HEADERS_ROUND_SIZE = IMAGE_NT_HEADERS_PADDING_END-IMAGE_DOS_HEADER
print_value_x32 "IMAGE_HEADERS_ROUND_SIZE          = ", IMAGE_HEADERS_ROUND_SIZE

HEADER_SECTION_END:
HEADER_IMAGE_SIZE = (((HEADER_SECTION_END-IMAGE_DOS_HEADER)+(SECTION_ALIGNMENT-1))/SECTION_ALIGNMENT)*SECTION_ALIGNMENT

CODE:
CODE.RVA = HEADER_IMAGE_SIZE
print_value_x32 "CODE                              = ", CODE
print_value_x32 "CODE RVA                          = ", CODE.RVA

start:
start.RVA = (start-CODE)+CODE.RVA

  mov    eax,0x2a            ; db 0xb8, 0x2a, 0x00, 0x00, 0x00
  sub    rsp,0x20            ; db 0x48, 0x83, 0xec, 0x20
  mov    ecx,eax             ; db 0x89, 0xc1
  call   qword [rip+0x1037]  ; db 0xff, 0x15, 0x37, 0x10, 0x00, 0x00
  add    rsp,0x20            ; db 0x48, 0x83, 0xc4, 0x20

CODE_END:
CODE_SIZE = CODE_END-CODE

print_value_x32 "CODE_SIZE                         = ", CODE_SIZE

CODE_PADDING:
  align_section

CODE_FILE_END:
CODE_FILE_SIZE = (((CODE_FILE_END-CODE)+(FILE_ALIGNMENT-1))/FILE_ALIGNMENT)*FILE_ALIGNMENT
print_value_x32 "CODE_FILE_SIZE                    = ", CODE_FILE_SIZE

CODE_SECTION_END:
CODE_IMAGE_SIZE = (((CODE_SECTION_END-CODE)+(SECTION_ALIGNMENT-1))/SECTION_ALIGNMENT)*SECTION_ALIGNMENT
print_value_x32 "CODE_IMAGE_SIZE                   = ", CODE_IMAGE_SIZE

IDATA:
IDATA.RVA = CODE.RVA + CODE_IMAGE_SIZE
print_value_x32 "IDATA                             = ", IDATA
print_value_x32 "IDATA RVA                         = ", IDATA.RVA

IMAGE_IMPORT_DIRECTORY:
IMAGE_IMPORT_DIRECTORY.RVA = (IMAGE_IMPORT_DIRECTORY-IDATA)+IDATA.RVA
print_value_x32 "IMAGE_IMPORT_DIRECTORY            = ", IMAGE_IMPORT_DIRECTORY

IMAGE_IMPORT_KERNEL32:
print_value_x32 "IMAGE_IMPORT_KERNEL32             = ", IMAGE_IMPORT_KERNEL32

  dd KERNEL32_IMPORT_LOOKUP_TABLE.RVA  ; u32 rvaImportLookupTable
  dd 0                                 ; u32 TimeDateStamp
  dd 0                                 ; u32 ForwarderChain
  dd KERNEL32_MODULE_NAME.RVA          ; u32 rvaModuleName
  dd KERNEL32_IMPORT_ADDRESS_TABLE.RVA ; u32 rvaImportAddressTable

IMAGE_IMPORT_END:
print_value_x32 "IMAGE_IMPORT_END                  = ", IMAGE_IMPORT_END

  dd 0 ; u32 rvaImportLookupTable
  dd 0 ; u32 TimeDateStamp
  dd 0 ; u32 ForwarderChain
  dd 0 ; u32 rvaModuleName
  dd 0 ; u32 rvaImportAddressTable

IMAGE_IMPORT_DIRECTORY_END:
IMAGE_IMPORT_DIRECTORY_SIZE = IMAGE_IMPORT_DIRECTORY_END-IMAGE_IMPORT_DIRECTORY

print_value_x32 "IMAGE_IMPORT_DIRECTORY_SIZE       = ", IMAGE_IMPORT_DIRECTORY_SIZE

KERNEL32_MODULE_NAME:
KERNEL32_MODULE_NAME.RVA =  (KERNEL32_MODULE_NAME-IDATA)+IDATA.RVA
print_value_x32 "KERNEL32_MODULE_NAME              = ", KERNEL32_MODULE_NAME
print_value_x32 "KERNEL32_MODULE_NAME RVA          = ", KERNEL32_MODULE_NAME.RVA

  db 'kernel32.dll', 0

KERNEL32_MODULE_NAME_PADDING:
  align 8

KERNEL32_IMPORT_LOOKUP_TABLE:
KERNEL32_IMPORT_LOOKUP_TABLE.RVA = (KERNEL32_IMPORT_LOOKUP_TABLE-IDATA)+IDATA.RVA
print_value_x32 "KERNEL32_IMPORT_LOOKUP_TABLE      = ", KERNEL32_IMPORT_LOOKUP_TABLE
print_value_x32 "KERNEL32_IMPORT_LOOKUP_TABLE RVA  = ", KERNEL32_IMPORT_LOOKUP_TABLE.RVA

  dq IMPORT_NAMES.ExitProcess.RVA
  dq 0 ; END

KERNEL32_IMPORT_ADDRESS_TABLE:
KERNEL32_IMPORT_ADDRESS_TABLE.RVA = (KERNEL32_IMPORT_ADDRESS_TABLE-IDATA)+IDATA.RVA
print_value_x32 "KERNEL32_IMPORT_ADDRESS_TABLE     = ", KERNEL32_IMPORT_ADDRESS_TABLE
print_value_x32 "KERNEL32_IMPORT_ADDRESS_TABLE RVA = ", KERNEL32_IMPORT_ADDRESS_TABLE.RVA

  dq IMPORT_NAMES.ExitProcess.RVA
  dq 0 ; END

IMPORT_NAMES:

  .ExitProcess:
  .ExitProcess.RVA = (IMPORT_NAMES.ExitProcess-IDATA)+IDATA.RVA

print_value_x32 "IMPORT_NAMES.ExitProcess          = ", IMPORT_NAMES.ExitProcess
print_value_x32 "IMPORT_NAMES.ExitProcess RVA      = ", IMPORT_NAMES.ExitProcess.RVA

  dw 0                 ; u16     Hint
  db 'ExitProcess', 0  ; cstring Name

IMPORT_NAMES_END:

IMPORT_NAMES_PADDING:
  align 8

IDATA_END:
IDATA_SIZE = IDATA_END-IDATA
print_value_x32 "IDATA_SIZE                        = ", IDATA_SIZE

IDATA_PADDING:
  align_section

IDATA_FILE_END:
IDATA_FILE_SIZE = (((IDATA_FILE_END-IDATA)+(FILE_ALIGNMENT-1))/FILE_ALIGNMENT)*FILE_ALIGNMENT
print_value_x32 "IDATA_FILE_SIZE                   = ", IDATA_FILE_SIZE

IDATA_SECTION_END:
IDATA_IMAGE_SIZE = (((IDATA_SECTION_END-IDATA)+(SECTION_ALIGNMENT-1))/SECTION_ALIGNMENT)*SECTION_ALIGNMENT
print_value_x32 "IDATA_IMAGE_SIZE                  = ", IDATA_IMAGE_SIZE

; SizeOfImage = Sum of sizes of all in-memory sections (aligned)
; Here, IDATA is the last section
IMAGE_SIZE = IDATA.RVA + (((IDATA_SIZE+(SECTION_ALIGNMENT-1))/SECTION_ALIGNMENT)*SECTION_ALIGNMENT)
print_value_x32 "IMAGE_SIZE                        = ", IMAGE_SIZE

FILE_END:
FILE_SIZE = FILE_END-IMAGE_DOS_HEADER
print_value_x32 "FILE_SIZE                         = ", FILE_SIZE


