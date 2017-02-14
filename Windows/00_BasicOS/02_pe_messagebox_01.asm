; 02_pe_messagebox_01.asm
;   - Put IDATA into CODE section
;   - Remove padding at end of CODE section
;   - Remove DOS program (don't care)

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
MODULE_NAME_SIZE   = 256

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
  ; Subsystem
  .IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
  .IMAGE_SUBSYSTEM_WINDOWS_CUI = 3

  db 0x0b, 0x02                                     ; u16 Magic
  db 0x01                                           ; u8  MajorLinkerVersion
  db 0x47                                           ; u8  MinorLinkerVersion
  dd CODE_SIZE                                      ; u32 SizeOfCode
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
  dw .IMAGE_SUBSYSTEM_WINDOWS_GUI                   ; u16 Subsystem
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

IMAGE_DATA_DIRECTORIES_END:
IMAGE_DATA_DIRECTORIES_COUNT = (IMAGE_DATA_DIRECTORIES_END-IMAGE_DATA_DIRECTORIES)/8

IMAGE_OPTIONAL_HEADER_END:
IMAGE_OPTIONAL_HEADER_SIZE = IMAGE_OPTIONAL_HEADER_END-IMAGE_OPTIONAL_HEADER
; assert (IMAGE_OPTIONAL_HEADER_SIZE = 0xF0)

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

SECTION_TABLE_ENTRY_CODE:

  db '.code',0,0,0                                  ; char Name[8]
  dd CODE_SIZE                                      ; u32  VirtualSize
  dd CODE.RVA                                       ; u32  VirtualAddress
  dd CODE_SIZE                                      ; u32  SizeOfRawData
  dd CODE                                           ; u32  PointerToRawData
  dd 0                                              ; u32  PointerToRelocations
  dd 0                                              ; u32  PointerToLinenumbers
  dw 0                                              ; u16  NumberOfRelocations
  dw 0                                              ; u16  NumberOfLineNumbers
  dd SECTION_TABLE.IMAGE_SCN_CNT_CODE \
   + SECTION_TABLE.IMAGE_SCN_MEM_EXECUTE \
   + SECTION_TABLE.IMAGE_SCN_MEM_READ \
   + SECTION_TABLE.IMAGE_SCN_MEM_WRITE; u32 Characteristics

SECTION_TABLE_ENTRY_CODE_END:
SECTION_TABLE_ENTRY_CODE_SIZE = SECTION_TABLE_ENTRY_CODE_END - SECTION_TABLE_ENTRY_CODE
assert (SECTION_TABLE_ENTRY_CODE_SIZE = 0x28)

SECTION_TABLE_ENTRY_BSS:

  db '.bss',0,0,0,0                                 ; char Name[8]
  dd BSS_IMAGE_SIZE                                 ; u32  VirtualSize
  dd BSS.RVA                                        ; u32  VirtualAddress
  dd 0                                              ; u32  SizeOfRawData
  dd 0                                              ; u32  PointerToRawData
  dd 0                                              ; u32  PointerToRelocations
  dd 0                                              ; u32  PointerToLinenumbers
  dw 0                                              ; u16  NumberOfRelocations
  dw 0                                              ; u16  NumberOfLineNumbers
  dd SECTION_TABLE.IMAGE_SCN_CNT_UNINITIALIZED_DATA \
   + SECTION_TABLE.IMAGE_SCN_MEM_READ \
   + SECTION_TABLE.IMAGE_SCN_MEM_WRITE ; u32 Characteristics

SECTION_TABLE_ENTRY_BSS_END:
SECTION_TABLE_ENTRY_BSS_SIZE = SECTION_TABLE_ENTRY_BSS_END - SECTION_TABLE_ENTRY_BSS
assert (SECTION_TABLE_ENTRY_BSS_SIZE = 0x28)

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

start:
start.RVA = (start-CODE)+CODE.RVA

  sub    rsp,0x28

  xor rcx, rcx                                           ; _In_opt_ HMODULE hModule
  lea rdx, [ rip + (g_ModuleName-((@f-CODE)+CODE.RVA)) ] ; _Out_    LPTSTR  lpFilename
  @@:
  mov r8d, MODULE_NAME_SIZE                              ;  _In_     DWORD   nSize

  call qword [ rip + (GetModuleFileName-((@f-CODE)+CODE.RVA))  ] 
  @@:

  xor ecx, ecx                                          ; _In_opt_ HWND    hWnd
  lea rdx, [MsgBoxText]                                 ; _In_opt_ LPCTSTR lpText
  lea r8, [ rip + (g_ModuleName-((@f-CODE)+CODE.RVA)) ] ; _In_opt_ LPCTSTR lpCaption
  @@:
  xor r9d, r9d                                          ; _In_     UINT    uType

  call qword [ rip + (MessageBox-((@f-CODE)+CODE.RVA))  ] 
  @@:

  ; Exit
  mov  eax,0x2a
  mov  ecx,eax
  call qword [ rip + (ExitProcess-((@f-CODE)+CODE.RVA))  ] 
  @@:

  add    rsp,0x28

  ; DATA: (it's in the same section, so let assembler work it address.)
  MsgBoxText db "Hello, World!",0 

  ;
  ; IDATA (.idata) embedded inside CODE (.code) section
  ; - Note characteristics of .code section changed (+write)
  ;

  IDATA:
  IDATA.RVA = CODE.RVA + (IDATA-CODE)
  
  IMAGE_IMPORT_DIRECTORY:
  IMAGE_IMPORT_DIRECTORY.RVA = (IMAGE_IMPORT_DIRECTORY-IDATA)+IDATA.RVA
  
  IMAGE_IMPORT_KERNEL32:
  
    dd KERNEL32_IMPORT_LOOKUP_TABLE.RVA  ; u32 rvaImportLookupTable
    dd 0                                 ; u32 TimeDateStamp
    dd 0                                 ; u32 ForwarderChain
    dd KERNEL32_MODULE_NAME.RVA          ; u32 rvaModuleName
    dd KERNEL32_IMPORT_ADDRESS_TABLE.RVA ; u32 rvaImportAddressTable
  
  IMAGE_IMPORT_USER32:
  
    dd USER32_IMPORT_LOOKUP_TABLE.RVA    ; u32 rvaImportLookupTable
    dd 0                                 ; u32 TimeDateStamp
    dd 0                                 ; u32 ForwarderChain
    dd USER32_MODULE_NAME.RVA            ; u32 rvaModuleName
    dd USER32_IMPORT_ADDRESS_TABLE.RVA   ; u32 rvaImportAddressTable
  
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
  
  USER32_MODULE_NAME:
  USER32_MODULE_NAME.RVA =  (USER32_MODULE_NAME-IDATA)+IDATA.RVA
  
    db 'user32.dll', 0
  
  MODULE_NAME_PADDING:
    align 8
  
  KERNEL32_IMPORT_LOOKUP_TABLE:
  KERNEL32_IMPORT_LOOKUP_TABLE.RVA = (KERNEL32_IMPORT_LOOKUP_TABLE-IDATA)+IDATA.RVA
  
    dq IMPORT_NAMES.ExitProcess.RVA
    dq IMPORT_NAMES.GetModuleFileNameA.RVA
    dq 0 ; END
  
  KERNEL32_IMPORT_ADDRESS_TABLE:
  KERNEL32_IMPORT_ADDRESS_TABLE.RVA = (KERNEL32_IMPORT_ADDRESS_TABLE-IDATA)+IDATA.RVA
  
    ExitProcess = ($-IDATA)+IDATA.RVA ; RVA
    dq IMPORT_NAMES.ExitProcess.RVA
  
    GetModuleFileName = ($-IDATA)+IDATA.RVA ; RVA
    dq IMPORT_NAMES.GetModuleFileNameA.RVA
    dq 0 ; END
  
  USER32_IMPORT_LOOKUP_TABLE:
  USER32_IMPORT_LOOKUP_TABLE.RVA = (USER32_IMPORT_LOOKUP_TABLE-IDATA)+IDATA.RVA
  
    dq IMPORT_NAMES.MessageBoxA.RVA
    dq 0 ; END
  
  USER32_IMPORT_ADDRESS_TABLE:
  USER32_IMPORT_ADDRESS_TABLE.RVA = (USER32_IMPORT_ADDRESS_TABLE-IDATA)+IDATA.RVA
  
    MessageBox = ($-IDATA)+IDATA.RVA ; RVA
    dq IMPORT_NAMES.MessageBoxA.RVA
    dq 0 ; END
  
  IMPORT_NAMES:
  
    ; kernel32.dll "ExitProcess"
  
    .ExitProcess:
    .ExitProcess.RVA = (IMPORT_NAMES.ExitProcess-IDATA)+IDATA.RVA
  
    dw 0                 ; u16     Hint
    db 'ExitProcess', 0  ; cstring Name
  
    ; kernel32.dll "GetModuleFileNameA"
  
    .GetModuleFileNameA:
    .GetModuleFileNameA.RVA = (IMPORT_NAMES.GetModuleFileNameA-IDATA)+IDATA.RVA
  
    dw 0                        ; u16     Hint
    db 'GetModuleFileNameA', 0  ; cstring Name
  
    ; user32.dll "MessageBoxA"
  
    .MessageBoxA:
    .MessageBoxA.RVA = (IMPORT_NAMES.MessageBoxA-IDATA)+IDATA.RVA
  
    dw 0                 ; u16     Hint
    db 'MessageBoxA', 0  ; cstring Name
  
  IMPORT_NAMES_END:
  
  IMPORT_NAMES_PADDING:
    align 8
  
  IDATA_END:
  IDATA_SIZE = IDATA_END-IDATA
  
CODE_END:
CODE_SIZE = CODE_END-CODE

CODE_SECTION_END:
CODE_IMAGE_SIZE = (((CODE_SECTION_END-CODE)+(SECTION_ALIGNMENT-1))/SECTION_ALIGNMENT)*SECTION_ALIGNMENT

FILE_END:
FILE_SIZE = FILE_END-IMAGE_DOS_HEADER

BSS:
BSS.RVA = CODE.RVA + CODE_IMAGE_SIZE
print_value_x32 "BSS.RVA        = ", BSS.RVA

  g_ModuleName = ($-BSS)+BSS.RVA ; RVA
  rb MODULE_NAME_SIZE

BSS_SECTION_END:
BSS_IMAGE_SIZE = (((BSS_SECTION_END-BSS)+(SECTION_ALIGNMENT-1))/SECTION_ALIGNMENT)*SECTION_ALIGNMENT

print_value_x32 "BSS_IMAGE_SIZE = ", BSS_IMAGE_SIZE

; SizeOfImage = Sum of sizes of all in-memory sections (aligned)
; Here, BSS is included, but does not exist in file.
IMAGE_SIZE = BSS.RVA + (((BSS_IMAGE_SIZE+(SECTION_ALIGNMENT-1))/SECTION_ALIGNMENT)*SECTION_ALIGNMENT)
