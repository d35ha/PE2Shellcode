bits 64
%include "stub_x64.inc"

Init:
    sub     rsp, 28h
    gs mov  rax, qword [TEB_PPEB_OFFSET]
    mov     rax, qword [rax + PEB_PLDR_OFFSET]
    mov     rsi, qword [rax + LDR_PIN_ORDER_MOD_LIST_OFFSET]
    lodsq
    xchg    rax, rsi
    lodsq
    mov     rbp, qword [rax + LDR_MODULE_BASE_OFFSET]
    mov     eax, dword [rbp + IMAGE_DOS_HEADER_LFANEW_OFFSET]
    mov     ebx, dword [rbp + rax + IMAGE_NT_HEADER_ENTRY_EXPORT_OFFSET]
    add     rbx, rbp
    mov     esi, [rbx + EXPORT_TABLE_ADDR_OF_NAMES_OFFSET]
    add     rsi, rbp
    xor     rcx, rcx
FindGetProcAddr:
    inc     rcx
    lodsd   
    add     rax, rbp
    cmp     dword [rax], STRING_OF_GETP
    jnz     FindGetProcAddr
    cmp     dword [rax + 0x4], STRING_OF_ROCA
    jnz     FindGetProcAddr
    cmp     dword [rax + 0x8], STRING_OF_DDRE
    jnz     FindGetProcAddr
    mov     esi, [rbx + EXPORT_TABLE_ADDR_OF_ORDINALS_OFFSET]
    add     rsi, rbp
    mov     cx, [rsi + rcx*2]
    dec     rcx
    mov     esi, [rbx + EXPORT_TABLE_ADDR_OF_FUNCTIONS_OFFSET]
    add     rsi, rbp
    mov     edi, [rsi + rcx*4]
    add     rdi, rbp
    jmp     GetPERawBase
PERawBase:
    pop     r15
    mov     rsi, r15
    mov     eax, dword [rsi + IMAGE_DOS_HEADER_LFANEW_OFFSET]
    add     rsi, rax
    call    VirtualAlloc
    db      'VirtualAlloc', 0h
VirtualAlloc:
    pop     rdx
    mov     rcx, rbp
    call    rdi
    mov     r12, rax
    mov     r9, PAGE_EXECUTE_READWRITE 
    mov     r8, MEM_COMMIT | MEM_RESERVE
    mov     edx, dword [rsi + IMAGE_NT_HEADER_SIZE_OF_IMAGE_OFFSET]
    mov     rcx, qword [rsi + IMAGE_NT_HEADER_BASE_OF_IMAGE_OFFSET]
    call    rax
    mov     rbx, rax
    test    rax, rax
    jnz     BuildIAT
    mov     r9, PAGE_EXECUTE_READWRITE 
    mov     r8, MEM_COMMIT | MEM_RESERVE
    mov     edx, dword [rsi + IMAGE_NT_HEADER_SIZE_OF_IMAGE_OFFSET]
    mov     rcx, 0
    call    r12
    mov     rbx, rax
    jmp     RelocatePE
Rva2Offset:
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    mov     r12, rsi
    add     r12, SIZE_OF_IMAGE_NT_HEADER
    xor     r13, r13
    mov     r13w, [rsi + IMAGE_NT_HEADER_NUMBER_OF_SECTIONS_OFFSET]
    xor     r10, r10
Rva2OffsetLoop:
    cmp     r10, r13
    je      Rva2OffsetEndLoop
    mov     r9d, dword [r12 + IMAGE_SECTION_HEADER_VIRTUAL_ADDR_OFFSET]
    mov     r8d, dword [r12 + IMAGE_SECTION_HEADER_VIRTUAL_SIZE_OFFSET]
    mov     r11d, dword [r12 + IMAGE_SECTION_HEADER_POINTER_TO_RAW_DATA_OFFSET]
    add     r8, r9
    add     r12, SIZE_OF_IMAGE_SECTION_HEADER
    inc     r10
    cmp     rax, r9
    jl      Rva2OffsetLoop
    cmp     rax, r8
    jge     Rva2OffsetLoop
    add     rax, r11
    sub     rax, r9
Rva2OffsetEndLoop:
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8    
    ret
RelocatePE:
    mov     r8, rbp
    mov     r9, rdi
    mov     eax, dword [rsi + IMAGE_NT_HEADER_ENTRY_RELOCS_OFFSET]
    call    Rva2Offset
    add     rax, r15
    mov     rbp, rax
    xor     rcx, rcx
RelocationLoop:
    cmp     ecx, dword [rsi + IMAGE_NT_HEADER_ENTRY_RELOCS_OFFSET + 4h]
    je      RelocationLoopEnd
    mov     rdx, rbp
    add     rdx, 8h
    mov     r14, rcx
    mov     edi, dword [rbp + 4h]
    sub     rdi, 8h
    shr     rdi, 1h
    xor     rcx, rcx
BlocksLoop:
    cmp     rcx, rdi
    je      BlocksLoopEnd
    xor     rax, rax
    mov     ax, [rdx]
    test    rax, rax
    jz      EscapeBlock
    and     ax, 0fffh
    add     eax, dword [rbp]
    call    Rva2Offset
    add     rax, r15
    mov     r10, qword [rsi + IMAGE_NT_HEADER_BASE_OF_IMAGE_OFFSET]
    sub     qword [rax], r10
    add     qword [rax], rbx
EscapeBlock:
    inc     rcx
    add     rdx, 2h
    jmp     BlocksLoop
BlocksLoopEnd:
    mov     rcx, r14
    add     ecx, dword [rbp + 4h]
    mov     r14d, dword [rbp + 4h]
    add     rbp, r14
    jmp     RelocationLoop
RelocationLoopEnd:
    mov     rbp, r8
    mov     rdi, r9
BuildIAT:
    call    LoadLibrary
    db      'LoadLibraryA', 0h
LoadLibrary:
    pop     rdx
    mov     rcx, rbp
    call    rdi
    mov     rdx, rax
    mov     eax, dword [rsi + IMAGE_NT_HEADER_ENTRY_IMPORT_OFFSET]
    call    Rva2Offset
    add     rax, r15
    mov     rcx, rax
DescriptorsLoop:
    mov     eax, dword [rcx + IMAGE_IMPORT_DESCRIPTOR_NAME_OFFSET]
    test    eax, eax
    jz      DescriptorsLoopEnd
    call    Rva2Offset
    add     rax, r15
    mov     r12, rcx
    mov     r13, rdx
    mov     rcx, rax
    call    rdx
    mov     rcx, r12
    mov     rdx, r13
    mov     r12, rdx
    mov     r13, rbx
    mov     r14, rbp
    mov     rbp, rax
    mov     eax, dword [rcx + IMAGE_IMPORT_DESCRIPTOR_FIRST_THUNK_OFFSET]
    call    Rva2Offset
    add     rax, r15
    mov     rdx, rax
    cmp     dword [rcx + IMAGE_IMPORT_DESCRIPTOR_TIME_STAMP_OFFSET], 0
    je      NotBoundedImport
    mov     eax, dword [rcx]
    call    Rva2Offset
    add     rax, r15
    mov     rbx, rax
    jmp     ThunkArraysLoop
NotBoundedImport:
    mov     rbx, rdx
ThunkArraysLoop:
    mov     rax, [rbx]
    test    rax, rax
    jz      ThunkArraysLoopEnd
    bt      rax, 3fh
    jc      ImportByOrdinal
    call    Rva2Offset
    add     rax, r15
    add     rax, 2h
    jmp     GetApiAddr
ImportByOrdinal:
    and     rax, 0ffffh
GetApiAddr:
    xchg    rcx, [rsp + 30h]
    xchg    rdx, [rsp + 38h]
    mov     rdx, rax
    mov     rcx, rbp
    call    rdi
    xchg    rcx, [rsp + 30h]
    xchg    rdx, [rsp + 38h]
    mov     qword [rdx], rax
    add     rbx, SIZE_OF_IMAGE_THUNK_DATA
    add     rdx, SIZE_OF_IMAGE_THUNK_DATA
    jmp     ThunkArraysLoop
ThunkArraysLoopEnd:
    mov     rdx, r12
    mov     rbx, r13
    mov     rbp, r14
    add     rcx, SIZE_OF_IMAGE_IMPORT_DESCRIPTOR
    jmp     DescriptorsLoop
DescriptorsLoopEnd:
    mov     r12, rdi
    mov     r13, rbp
    mov     rcx, rsi
    add     rcx, SIZE_OF_IMAGE_NT_HEADER
    xor     rax, rax
    xor     rdx, rdx
    mov     dx, word [rsi + IMAGE_NT_HEADER_NUMBER_OF_SECTIONS_OFFSET]
MapSectionLoop:
    cmp     rax, rdx
    je      MapSectionLoopEnd
    mov     rdi, rbx
    mov     rbp, rsi
    mov     rsi, r15
    mov     r14d, dword [rcx + IMAGE_SECTION_HEADER_POINTER_TO_RAW_DATA_OFFSET]
    add     rsi, r14
    mov     r14d, dword [rcx + IMAGE_SECTION_HEADER_VIRTUAL_ADDR_OFFSET]
    add     rdi, r14
    mov     r14, rcx
    mov     ecx, dword [rcx + IMAGE_SECTION_HEADER_SIZE_OF_RAW_DATA_OFFSET]
    rep     movsb
    mov     rcx, r14
    mov     rsi, rbp
    inc     rax
    add     rcx, SIZE_OF_IMAGE_SECTION_HEADER
    jmp     MapSectionLoop
MapSectionLoopEnd:
    mov     rdi, r12
    mov     rbp, r13
    mov     eax, dword [rsi + IMAGE_NT_HEADER_ADDR_OF_ENTRY_POINT_OFFSET]
    add     rax, rbx
    mov     rsi, rax
    call    VirtualFree
    db      'VirtualFree', 0h
VirtualFree:
    pop     rdx
    mov     rcx, rbp
    call    rdi
    mov     r8, MEM_RELEASE
    xor     rdx, rdx
    call    PushShellcodeBase
PushShellcodeBase:
    pop     rcx
    sub     rcx, PushShellcodeBase
    add     rsp, 28h
    push    rsi
    push    rax
    ret
GetPERawBase:
    call    PERawBase