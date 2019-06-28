bits 32
%include "stub_x32.inc"

Init:
    fs mov  eax, dword [TEB_PPEB_OFFSET]
    mov     eax, dword [eax + PEB_PLDR_OFFSET]
    mov     esi, dword [eax + LDR_PIN_ORDER_MOD_LIST_OFFSET]
    lodsd
    xchg    eax, esi
    lodsd
    mov     ebp, dword [eax + LDR_MODULE_BASE_OFFSET]
    mov     eax, dword [ebp + IMAGE_DOS_HEADER_LFANEW_OFFSET]
    mov     ebx, dword [ebp + eax + IMAGE_NT_HEADER_ENTRY_EXPORT_OFFSET]
    add     ebx, ebp
    mov     esi, [ebx + EXPORT_TABLE_ADDR_OF_NAMES_OFFSET]
    add     esi, ebp
    xor     ecx, ecx
FindGetProcAddr:
    inc     ecx
    lodsd   
    add     eax, ebp
    cmp     dword [eax], STRING_OF_GETP
    jnz     FindGetProcAddr
    cmp     dword [eax + 0x4], STRING_OF_ROCA
    jnz     FindGetProcAddr
    cmp     dword [eax + 0x8], STRING_OF_DDRE
    jnz     FindGetProcAddr
    mov     esi, [ebx + EXPORT_TABLE_ADDR_OF_ORDINALS_OFFSET]
    add     esi, ebp
    mov     cx, [esi + ecx*2]
    dec     ecx
    mov     esi, [ebx + EXPORT_TABLE_ADDR_OF_FUNCTIONS_OFFSET]
    add     esi, ebp
    mov     edi, [esi + ecx*4]
    add     edi, ebp
    jmp     GetPERawBase
PERawBase:
    mov     esi, [esp]
    add     esi, dword [esi + IMAGE_DOS_HEADER_LFANEW_OFFSET]
    call    VirtualAlloc
    db      'VirtualAlloc', 0h
VirtualAlloc:
    push    ebp
    call    edi
    push    eax
    push    PAGE_EXECUTE_READWRITE
    push    MEM_COMMIT | MEM_RESERVE
    push    dword [esi + IMAGE_NT_HEADER_SIZE_OF_IMAGE_OFFSET]
    push    dword [esi + IMAGE_NT_HEADER_BASE_OF_IMAGE_OFFSET]
    call    eax
    pop     ecx
    mov     ebx, eax
    test    eax, eax
    jnz     BuildIAT
    push    PAGE_EXECUTE_READWRITE
    push    MEM_COMMIT | MEM_RESERVE
    push    dword [esi + IMAGE_NT_HEADER_SIZE_OF_IMAGE_OFFSET]
    push    0
    call    ecx
    mov     ebx, eax
    jmp     RelocatePE
Rva2Offset:
    push    ebx
    push    edx
    push    ebp
    push    edi
    push    ecx
    mov     ecx, esi
    add     ecx, SIZE_OF_IMAGE_NT_HEADER
    xor     ebp, ebp
    mov     bp, [esi + IMAGE_NT_HEADER_NUMBER_OF_SECTIONS_OFFSET]
    push    ebp
    xor     ebp, ebp
Rva2OffsetLoop:
    cmp     ebp, dword [esp]
    je      Rva2OffsetEndLoop
    mov     edx, dword [ecx + IMAGE_SECTION_HEADER_VIRTUAL_ADDR_OFFSET]
    mov     ebx, dword [ecx + IMAGE_SECTION_HEADER_VIRTUAL_SIZE_OFFSET]
    mov     edi, dword [ecx + IMAGE_SECTION_HEADER_POINTER_TO_RAW_DATA_OFFSET]
    add     ebx, edx
    add     ecx, SIZE_OF_IMAGE_SECTION_HEADER
    inc     ebp
    cmp     eax, edx
    jl      Rva2OffsetLoop
    cmp     eax, ebx
    jge     Rva2OffsetLoop
    add     eax, edi
    sub     eax, edx
Rva2OffsetEndLoop:
    add     esp, 4h
    pop     ecx
    pop     edi
    pop     ebp
    pop     edx
    pop     ebx
    ret
RelocatePE:
    push    ebp
    push    edi
    mov     eax, dword [esi + IMAGE_NT_HEADER_ENTRY_RELOCS_OFFSET]
    call    Rva2Offset
    add     eax, [esp + 8h]
    mov     ebp, eax
    xor     ecx, ecx
RelocationLoop:
    cmp     ecx, dword [esi + IMAGE_NT_HEADER_ENTRY_RELOCS_OFFSET + 4h]
    je      RelocationLoopEnd
    mov     edx, ebp
    add     edx, 8h
    push    ecx
    mov     edi, dword [ebp + 4h]
    sub     edi, 8h
    shr     edi, 1h
    xor     ecx, ecx
BlocksLoop:
    cmp     ecx, edi
    je      BlocksLoopEnd
    xor     eax, eax
    mov     ax, [edx]
    test    eax, eax
    jz      EscapeBlock
    and     ax, 0fffh
    add     eax, dword [ebp]
    call    Rva2Offset
    add     eax, dword [esp + 0ch]
    push    ecx
    mov     ecx, dword [esi + IMAGE_NT_HEADER_BASE_OF_IMAGE_OFFSET]
    sub     dword [eax], ecx
    add     dword [eax], ebx
    pop     ecx
EscapeBlock:
    inc     ecx
    add     edx, 2h
    jmp     BlocksLoop
BlocksLoopEnd:
    pop     ecx
    add     ecx, dword [ebp + 4h]
    add     ebp, dword [ebp + 4h]
    jmp     RelocationLoop
RelocationLoopEnd:
    pop    edi
    pop    ebp
BuildIAT:
    call    LoadLibrary
    db      'LoadLibraryA', 0h
LoadLibrary:
    push    ebp
    call    edi
    mov     edx, eax
    mov     eax, dword [esi + IMAGE_NT_HEADER_ENTRY_IMPORT_OFFSET]
    call    Rva2Offset
    add     eax, [esp]
    mov     ecx, eax
DescriptorsLoop:
    mov     eax, dword [ecx + IMAGE_IMPORT_DESCRIPTOR_NAME_OFFSET]
    test    eax, eax
    jz      DescriptorsLoopEnd
    call    Rva2Offset
    add     eax, [esp]
    push    ecx
    push    edx
    push    eax
    call    edx
    pop     edx
    pop     ecx
    push    edx
    push    ebx
    push    ebp
    mov     ebp, eax
    mov     eax, dword [ecx + IMAGE_IMPORT_DESCRIPTOR_FIRST_THUNK_OFFSET]
    call    Rva2Offset
    add     eax, [esp + 0ch]
    mov     edx, eax
    cmp     dword [ecx + IMAGE_IMPORT_DESCRIPTOR_TIME_STAMP_OFFSET], 0
    je      NotBoundedImport
    mov     eax, dword [ecx]
    call    Rva2Offset
    add     eax, [esp + 0ch]
    mov     ebx, eax
    jmp     ThunkArraysLoop
NotBoundedImport:
    mov     ebx, edx
ThunkArraysLoop:
    mov     eax, [ebx]
    test    eax, eax
    jz      ThunkArraysLoopEnd
    bt      eax, 1fh
    jc      ImportByOrdinal
    call    Rva2Offset
    add     eax, [esp + 0ch]
    add     eax, 2h
    jmp     GetApiAddr
ImportByOrdinal:
    and     eax, 0ffffh
GetApiAddr:
    push    ecx
    push    edx
    push    eax
    push    ebp
    call    edi
    pop     edx
    pop     ecx
    mov     dword [edx], eax
    add     ebx, SIZE_OF_IMAGE_THUNK_DATA
    add     edx, SIZE_OF_IMAGE_THUNK_DATA
    jmp     ThunkArraysLoop
ThunkArraysLoopEnd:
    pop     ebp
    pop     ebx
    pop     edx
    add     ecx, SIZE_OF_IMAGE_IMPORT_DESCRIPTOR
    jmp     DescriptorsLoop
DescriptorsLoopEnd:
    push    edi
    push    ebp
    mov     ecx, esi
    add     ecx, SIZE_OF_IMAGE_NT_HEADER
    xor     eax, eax
    xor     edx, edx
    mov     dx, word [esi + IMAGE_NT_HEADER_NUMBER_OF_SECTIONS_OFFSET]
MapSectionLoop:
    cmp     eax, edx
    je      MapSectionLoopEnd
    mov     edi, ebx
    mov     ebp, esi
    mov     esi, [esp + 8h]
    add     esi, dword [ecx + IMAGE_SECTION_HEADER_POINTER_TO_RAW_DATA_OFFSET]
    add     edi, dword [ecx + IMAGE_SECTION_HEADER_VIRTUAL_ADDR_OFFSET]
    push    dword [ecx + IMAGE_SECTION_HEADER_SIZE_OF_RAW_DATA_OFFSET]
    xchg    ecx, [esp]
    rep     movsb
    pop     ecx
    mov     esi, ebp
    inc     eax
    add     ecx, SIZE_OF_IMAGE_SECTION_HEADER
    jmp     MapSectionLoop
MapSectionLoopEnd:
    pop     ebp
    pop     edi
    mov     eax, dword [esi + IMAGE_NT_HEADER_ADDR_OF_ENTRY_POINT_OFFSET]
    add     eax, ebx
    mov     dword [esp], eax
    call    VirtualFree
    db      'VirtualFree', 0h
VirtualFree:
    push    ebp
    call    edi
    pop     esi
    push    MEM_RELEASE
    push    0
    call    PushShellcodeBase
PushShellcodeBase:
    sub     dword [esp], PushShellcodeBase
    push    esi
    push    eax
    ret
GetPERawBase:
    call    PERawBase