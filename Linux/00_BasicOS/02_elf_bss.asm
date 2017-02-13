; https://gist.github.com/warabanshi/4436016

use64
org 0x08048000

ehdr:                         ; ELF64_Ehdr(ELF header)

  db  0x7f, "ELF", 2, 1, 1    ; e_ident
  times 9 db  0               ; e_ident
  dw  2                       ; u16 e_type
  dw  0x3e                    ; u16 e_machine /usr/include/linux/elf-em.h ; 62 = x86-64
  dd  0x01                    ; u32 e_version
  dq  _start                  ; u64 e_entry
  dq  phdr - $$               ; u64 e_phoff
  dq  0                       ; u64 e_shoff
  dd  0                       ; u32 e_flags
  dw  ehdrsize                ; u16 e_ehsize
  dw  phdrsize                ; u16 e_phentisize
  dw  2                       ; u16 e_phnum
  dw  0                       ; u16 e_shentsize
  dw  0                       ; u16 e_shnum
  dw  0                       ; u16 e_shstrndx

ehdrsize = $ - ehdr

phdr:                         ; ELF64_Phdr(program header)

  dd  1                       ; u32 p_type
  dd  0x05                    ; u32 p_flags
  dq  0                       ; u64 p_offset
  dq  $$                      ; u64 p_vaddr
  dq  $$                      ; u64 p_paddr
  dq  filesize                ; u64 p_filesz
  dq  filesize                ; u64 p_memsz
  dq  0x200000                ; u64 p_align

phdrsize = $ - phdr

  dd  1                       ; u32 p_type
  dd  0x06                    ; u32 p_flags
  dq  0x0                     ; u64 p_offset
  dq  $$ + 0x200000           ; u64 p_vaddr
  dq  $$ + 0x200000           ; u64 p_paddr
  dq  0                       ; u64 p_filesz
  dq  0x30000                 ; u64 p_memsz
  dq  0x200000                ; u64 p_align

_start:

  mov qword [value], 42
  mov rax, 231           ; sys_exit_group
  mov rdi, qword [value] ; int status
  syscall

filesize = $ - $$

org 0x08248000
bss:

value rq 1
      rq 2048
