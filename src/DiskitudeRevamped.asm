; Diskitude Revamped native x86-64 source
; Output: unpacked PE32+ GUI executable, assembled directly by NASM.

BITS 64
DEFAULT REL
; Bulk enumeration with a bounded worker pool.
%define THREAD_WORKERS 8
%define SCAN_BATCH 128
%define ENUM_BUFFER_BYTES 16384

IMAGE_BASE          equ 0x0000000140000000
TEXT_RVA            equ 0x1000
FILE_ALIGNMENT      equ 0x200
SECTION_ALIGNMENT   equ 0x1000
%ifdef DEV_BUILD
TEXT_RAW_SIZE       equ 0x3000
BSS_RVA             equ 0x5000
%else
TEXT_RAW_SIZE       equ text_end-text_start
BSS_RVA             equ 0x3000
%endif
API_CENTER          equ 0x80

; Node and persistent enumeration frame (56 bytes); path follows inline.
N_SIZE              equ 0
N_FLOAT             equ 8
N_IS_FILE           equ 12
N_IS_FILE_BYTES     equ 1
N_PATHLEN           equ 14
N_NEXT              equ 24
N_CHILD             equ 32
N_BYTES             equ 56

; Every active directory owns a buffer so its unconsumed records survive descent.
F_HANDLE            equ 40
F_PARENT            equ 16
; A worker flushes its pending file list before changing directories.
C_HEAD              equ 16
C_DELTA             equ 24
C_COUNT             equ 32
F_BUFFER            equ 48
ENUM_BYTES          equ ENUM_BUFFER_BYTES
B_CURSOR            equ 0
B_IOSTATUS          equ 8
B_DATA              equ 24

; Navigation frame (32 bytes)
H_ROOT              equ 0
H_VIEW              equ 8
H_PREV              equ 24
H_BYTES             equ 32

; Geometry is four floats (16 bytes); traversal cursors are local, not view state.
V_INNER             equ 0
V_OUTER             equ 4
V_START             equ 8
V_SWEEP             equ 12
V_BYTES             equ 16

; API table. Its ordering matches resolver_records exactly.
api_CreateCompatibleDC               equ 0*8
api_SelectObject                     equ 1*8
api_DeleteObject                     equ 2*8
api_CreateFontIndirectW              equ 3*8
api_CreateDIBSection                 equ 4*8
api_GdiFlush                         equ 5*8
api_GetDeviceCaps                    equ 6*8
api_SetBkMode                        equ 7*8
api_SetTextColor                     equ 8*8
api_BitBlt                           equ 9*8
api_GdiplusStartup                   equ 10*8
api_GdipCreateFromHDC                equ 11*8
api_GdipSetSmoothingMode             equ 12*8
api_GdipCreatePen1                   equ 13*8
api_GdipCreateSolidFill              equ 14*8
api_GdipSetSolidFillColor            equ 15*8
api_GdipCreatePath                   equ 16*8
api_GdipAddPathArc                   equ 17*8
api_GdipStartPathFigure              equ 18*8
api_GdipClosePathFigure              equ 19*8
api_GdipFillPath                     equ 20*8
api_GdipDrawPath                     equ 21*8
api_GdipDeletePath                   equ 22*8
api_GdipDeleteGraphics               equ 23*8
api_SetCursor                        equ 24*8
api_SetTimer                         equ 25*8
api_GetMessageW                      equ 26*8
api_SetProcessDPIAware               equ 27*8
api_LoadCursorW                      equ 28*8
api_LoadIconW                        equ 29*8
api_ShowWindow                       equ 30*8
api_CreateWindowExW                  equ 31*8
api_RegisterClassW                   equ 32*8
api_ValidateRect                     equ 33*8
api_DefWindowProcW                   equ 34*8
api_DispatchMessageW                 equ 35*8
api_wsprintfW                        equ 36*8
api_GetDC                            equ 37*8
api_SystemParametersInfoW            equ 38*8
api_InvalidateRect                   equ 39*8
api_SendMessageW                     equ 40*8
api_OpenClipboard                    equ 41*8
api_EmptyClipboard                   equ 42*8
api_SetClipboardData                 equ 43*8
api_CloseClipboard                   equ 44*8
api_DrawTextW                        equ 45*8
api_SetScrollInfo                    equ 46*8
api_GetProcessHeap                   equ 47*8
api_GetTickCount                     equ 48*8
api_HeapFree                         equ 49*8
api_HeapAlloc                        equ 50*8
api_InitializeCriticalSection        equ 51*8
api_GetCommandLineW                  equ 52*8
api_ExitProcess                      equ 53*8
api_CreateFileW                      equ 54*8
api_EnterCriticalSection             equ 55*8
api_Sleep                            equ 56*8
api_CloseHandle                      equ 57*8
api_LeaveCriticalSection             equ 58*8
api_QueueUserWorkItem                equ 59*8
api_GetModuleFileNameW               equ 60*8
api_GlobalAlloc                      equ 61*8
api_GlobalLock                       equ 62*8
api_GlobalUnlock                     equ 63*8
api_GlobalFree                       equ 64*8
api_GetLogicalDrives                 equ 65*8
api_SetErrorMode                     equ 66*8
api_NtQueryDirectoryFile             equ 67*8
api_RegGetValueA                     equ 68*8
api_DwmSetWindowAttribute            equ 69*8
api_CoInitialize                     equ 70*8
api_CoTaskMemFree                    equ 71*8
api_ShellExecuteW                    equ 72*8
api_CommandLineToArgvW               equ 73*8
api_SHGetPathFromIDListW             equ 74*8
api_SHBrowseForFolderW               equ 75*8
api_SHGetSpecialFolderLocation       equ 76*8
api_ILIsEqual                        equ 77*8
API_COUNT equ 78

%macro API 1
%if (api_%1 - API_CENTER) >= -128 && (api_%1 - API_CENTER) <= 127
    call qword [rbx + api_%1 - API_CENTER]
%else
    call qword [rel api_table + api_%1]
%endif
%endmacro

%macro LOAD_BASES 0
    lea rbx,[rel api_table + API_CENTER]
    lea rbp,[rel globals_center]
%endmacro

%macro LOAD_CONSTANTS 0
    lea r15,[rel float_constants]
%endmacro

SECTION .headers progbits start=0 vstart=IMAGE_BASE align=1
    dw 0x5A4D
; The native PE loader needs MZ and e_lfanew; bootstrap names use the intervening
; DOS-only fields. All three names are normal mapped import data, never decoded.
hint_LoadLibraryA:  dw 0
    db 'LoadLibraryA',0
hint_GetProcAddress: dw 0
    db 'GetProcAddress',0
dll_kernel32:       db 'KERNEL32.dll',0
size_units:         db 'KMGTPE'
    times 60-($-$$) db 0
    dd pe_header - IMAGE_BASE

pe_header:
    db 'PE',0,0
    dw 0x8664                         ; IMAGE_FILE_MACHINE_AMD64
    dw 1                              ; one compact code/data image section
    dd 0                              ; deterministic timestamp
    dd 0,0
    dw 0x80                           ; PE32+ base header plus export/import directories
    dw 0x0022                         ; executable and large-address-aware

optional_header:
    dw 0x020B                         ; PE32+
    db 3,2                            ; linker version (NASM 3.02)
    dd TEXT_RAW_SIZE                  ; SizeOfCode
    dd 0                              ; SizeOfInitializedData
    dd bss_end - bss_start            ; SizeOfUninitializedData
    dd entry_point - IMAGE_BASE       ; AddressOfEntryPoint
    dd TEXT_RVA                       ; BaseOfCode
    dq IMAGE_BASE
    dd SECTION_ALIGNMENT,FILE_ALIGNMENT
    dw 6,1                            ; Windows 7+ subsystem baseline
    dw 0,0                            ; image version
    dw 6,1                            ; subsystem version
    dd 0                              ; Win32VersionValue
    dd ((bss_end - bss_start + BSS_RVA + SECTION_ALIGNMENT - 1) & ~(SECTION_ALIGNMENT - 1))
    dd FILE_ALIGNMENT                 ; SizeOfHeaders
    dd 0                              ; checksum
    dw 2                              ; Windows GUI
    dw 0x0100                         ; NX compatible; fixed image has no relocations
    dq 0x100000,0x1000                ; stack reserve/commit
    dq 0x100000,0x1000                ; heap reserve/commit
    dd 0,2                            ; only export and import directories are present
    dd 0,0                            ; export
    dd import_directory - IMAGE_BASE,import_directory_end - import_directory

section_table:
    db '.text',0,0,0
    dd BSS_RVA-TEXT_RVA+bss_end-bss_start
    dd TEXT_RVA
    dd TEXT_RAW_SIZE
    dd FILE_ALIGNMENT
    dd 0,0
    dw 0,0
    dd 0xE0000020                     ; code, execute, read, write; zero tail holds state

; Mapped space in the aligned PE header carries read-only numeric tables. This is
; ordinary mapped PE data, not a compressed stream or an unpacking stub.
float_constants:
c_one:              dd 0x3F800000
c_three:            dd 0x40400000
c_eight:            dd 0x41000000
c_nine:             dd 0x41100000
c_ten:              dd 0x41200000
c_ring_width:       dd 0x41C80000 ; 25 logical pixels per ring
c_hundred:          dd 0x42C80000
c_half:             dd 0x3F000000
c_neg_half:         dd 0xBF000000
c_min_chart:        dd 0x43A00000 ; 320 logical pixels; scroll instead of overlapping
c_degrees:          dd 0x42652EE1
c_ninety:           dd 0x42B40000
c_pi:               dd 0x40490FDB
c_two_pi:           dd 0x40C90FDB
c_two_pi_low:       dd 0x40C90FD9
c_epsilon:          dd 0x358637BD
c_point001:         dd 0x3A83126F
c_inv96:            dd 0x3C2AAAAB
c_2pow64:           dq 0x43F0000000000000
size_thresholds:    dd 0x44800000 ; one 1024 divisor for every binary size unit
default_view:       dd 0,0x42480000,0,0x40C90FDB
color_palette:      db 0xFF,0xFF,0xFF, 0xBF,0xDF,0xFF, 0x3F,0x99,0xFF, 0x1F,0x5F,0xFF
                    db 0x7F,0x7F,0x7F, 0xDF,0xEF,0xFF, 0x9F,0xCC,0xFF, 0x00,0x00,0x00

; Frequently used UI text fills the rest of the mapped header. ASCII is widened
; into zero-filled UTF-16 state once at startup.
header_ascii_strings:
s_initial_path:     db 'C:\',0
s_title:            db 'Diskitude',0
s_scanning:         db 'Scanning...',0
s_expand_hint:      db 'Right-click: expand',0
s_back_hint:        db 'Right-click: back',0
s_locate_prefix:    db 'Ctrl+click: locate ',0
s_scanning_prefix:  db 'Scanning ',0
s_scan_of_prefix:   db 'Scan of ',0
s_browse_title:     db 'Folder or This PC:',0
s_explorer:         db 'explorer',0
header_ascii_strings_end:


    times FILE_ALIGNMENT-($-$$) db 0

SECTION .text progbits start=FILE_ALIGNMENT vstart=IMAGE_BASE+TEXT_RVA align=1
text_start:

; The process imports only these two bootstrap functions. Every application API is
; resolved from an explicit hash list below; GetProcAddress handles forwarded exports.
entry_point:
    sub rsp,40
    call resolve_apis
    test eax,eax
    jz .failure
    LOAD_BASES
    LOAD_CONSTANTS
    add rsp,40
    jmp app_main
.failure:
    add rsp,40
    ret

; Resolve nine modules and 78 named exports. ROR13 hashes are build-time constants;
; names are never stored in the executable and no payload is compressed or unpacked.
resolve_apis:
    sub rsp,56
    lea rsi,[rel resolver_records]
    lea r12,[rel api_table]
    push byte 9
    pop r15
.module:
    lodsb
    movzx r13d,al
    mov rcx,rsi
    call qword [rel iat_LoadLibraryA]
    test rax,rax
    jz .fail
    mov r14,rax
    mov [rel shell_module],rax       ; SHELL32 is resolved last
.skip_name:
    lodsb
    test al,al
    jnz .skip_name
    mov eax,[r14+0x3C]
    mov eax,[r14+rax+0x88]
    test eax,eax
    jz .fail
    lea r10,[r14+rax]
    mov eax,[r10+0x20]
    lea rax,[r14+rax]
    mov [rsp+32],rax
    mov eax,[r10+0x18]
    mov [rsp+40],eax
.function:
    lodsd
    mov edi,eax
    mov r10,[rsp+32]
    mov r9d,[rsp+40]
.find_name:
    dec r9d
    js .fail
    mov eax,[r10+r9*4]
    lea r8,[r14+rax]
    mov rdx,r8
    call hash_export_name
    cmp eax,edi
    jne .find_name
    mov rcx,r14
    mov rdx,r8
    call qword [rel iat_GetProcAddress]
    test rax,rax
    jz .fail
    mov [r12],rax
    add r12,8
    dec r13d
    jnz .function
    dec r15d
    jnz .module
    push byte 1
    pop rax
    jmp .done
.fail:
    xor eax,eax
.done:
    add rsp,56
    ret

hash_export_name:
    xor eax,eax
.next:
    movzx ecx,byte [rdx]
    inc rdx
    test ecx,ecx
    jz .done
    ror eax,13
    add eax,ecx
    jmp .next
.done:
    ret

; Application implementation follows the resolver.

%define G(x) [rbp + x - globals_center]
%define C(x) [r15 + x - float_constants]

; Tail-call wrappers use the shadow space already reserved by their callers.
heap_alloc_zeroed:
    mov r8,rcx
    push byte 8
    pop rdx
    mov rcx,G(process_heap)
    jmp qword [rel api_table + api_HeapAlloc]

heap_free:
    mov r8,rcx
    xor edx,edx
    mov rcx,G(process_heap)
    jmp qword [rel api_table + api_HeapFree]

; Uncontended locking stays in user space. Recursive entry is required by
; hover/animation -> update_hover -> render_scene and by Shell UI callbacks.
state_lock:
    lea rcx,[rel state_critical_section]
    jmp qword [rel api_table + api_EnterCriticalSection]

state_unlock:
    lea rcx,[rel state_critical_section]
    jmp qword [rel api_table + api_LeaveCriticalSection]

; RCX -> UTF-16 string, EAX <- character count.
wcslen16:
    xor eax,eax
    dec eax
.loop:
    inc eax
    cmp word [rcx+rax*2],0
    jne .loop
    ret

; Convert a node's unsigned size through x87 extended precision. RCX = node.
uint64_to_float:
    fild qword [rcx+N_SIZE]
    cmp qword [rcx+N_SIZE],0
    jns .store
    fadd qword C(c_2pow64)
.store:
    fstp dword [rcx+N_FLOAT]
    ret

initialize_static_state:
    push rsi
    push rdi
    lea rsi,[rel header_ascii_strings]
    lea rdi,[rel wide_header_strings]
    mov ecx,header_ascii_strings_end-header_ascii_strings
    xor eax,eax
.widen_header:
    lodsb
    stosw
    loop .widen_header
    lea rsi,[rel tail_ascii_strings]
    ; RDI already points at the adjacent wide_tail_strings.
    mov ecx,tail_ascii_strings_end-tail_ascii_strings
.widen_tail:
    lodsb
    stosw
    loop .widen_tail
    movups xmm0,C(default_view)
    movups G(current_view),xmm0
    mov byte [rel bitmap_info],40
    mov dword [rel bitmap_info+12],0x00200001
    mov byte [rel wnd_class],3
    lea rax,[rel window_proc]
    mov [rel wnd_class+8],rax
    lea rax,[rel w_title]
    mov [rel wnd_class+64],rax
    lea rax,[rel browse_selection_path]
    mov [rel browse_info+16],rax
    lea rax,[rel w_browse_title]
    mov [rel browse_info+24],rax
    mov dword [rel browse_info+32],0x240
    lea rax,[rel browse_callback]
    mov [rel browse_info+40],rax
    pop rdi
    pop rsi
    ret

; BFFCALLBACK: RCX=dialog, EDX=message, R8=PIDL.
browse_callback:
    push rbx
    push rbp
    sub rsp,56
    mov [rsp+32],rcx
    mov [rsp+40],r8
    LOAD_BASES
    cmp edx,1
    jne .selection_changed
    mov edx,0x467
    push byte 1
    pop r8
    lea r9,[rel w_initial_path]
    API SendMessageW
    jmp .done
.selection_changed:
    cmp edx,2
    jne .done
    mov rcx,r8
    lea rdx,[rel browse_selection_path]
    API SHGetPathFromIDListW
    test eax,eax
    jnz .enable
    mov rdx,G(computer_pidl)
    test rdx,rdx
    jz .enable
    mov rcx,[rsp+40]
    API ILIsEqual
.enable:
    mov r9d,eax
    mov rcx,[rsp+32]
    mov edx,0x465
    xor r8d,r8d
    API SendMessageW
.done:
    xor eax,eax
    add rsp,56
    pop rbp
    pop rbx
    ret

; Select a command-line/folder-dialog root, create the first frame, and launch the scanner.
select_root_and_start_scan:
    sub rsp,56
    mov rsi,G(command_line_root)
    test rsi,rsi
    jnz .have_root
    xor ecx,ecx
    API CoInitialize
    xor ecx,ecx
    push byte 17
    pop rdx
    lea r8,G(computer_pidl)
    API SHGetSpecialFolderLocation
.pick:
    lea rcx,[rel browse_info]
    API SHBrowseForFolderW
    test rax,rax
    jnz .picked
    xor ecx,ecx
    API ExitProcess
.picked:
    mov rdi,rax
    mov rcx,rax
    lea rsi,[rel root_path_buffer]
    mov rdx,rsi
    API SHGetPathFromIDListW
    test eax,eax
    setz byte G(computer_mode)
    jnz .valid
    mov rcx,rdi
    mov rdx,G(computer_pidl)
    API ILIsEqual
    test eax,eax
    jnz .valid
    mov rcx,rdi
    API CoTaskMemFree
    jmp .pick
.valid:
    mov G(command_line_root),rsi
    mov rcx,rdi
    API CoTaskMemFree
    mov rcx,G(computer_pidl)
    API CoTaskMemFree
.have_root:
    mov rcx,rsi
    xor edx,edx
    xor r8d,r8d
    call scan_root_create
    mov G(scan_frame_stack),rax
    mov G(scan_tree_root),rax
    mov G(display_root),rax
    mov byte G(scan_active),1
    lea rcx,[rel scanner_thread_proc]
    xor edx,edx
    push byte 16                       ; WT_EXECUTELONGFUNCTION: coordinator waits for F5
    pop r8
    API QueueUserWorkItem
    add rsp,56
    ret

app_main:
    sub rsp,0xA8
    call initialize_static_state
    API GetCommandLineW
    mov rcx,rax
    lea rdx,[rsp+0x98]
    API CommandLineToArgvW
    cmp dword [rsp+0x98],2
    jl .no_argument
    mov rax,[rax+8]
    mov G(command_line_root),rax
.no_argument:
    API SetProcessDPIAware
    lea rcx,[rel state_critical_section]
    API InitializeCriticalSection
    API GetProcessHeap
    mov G(process_heap),rax
    push byte 1
    pop rcx
    API SetErrorMode
    call select_root_and_start_scan

    mov rcx,G(shell_module)
    mov edx,0x113
    API LoadIconW
    mov [rel wnd_class+32],rax
    xor ecx,ecx
    mov edx,0x7F00
    API LoadCursorW
    mov G(arrow_cursor),rax
    mov [rel wnd_class+40],rax
    xor ecx,ecx
    mov edx,0x7F89
    API LoadCursorW
    mov G(hand_cursor),rax
    lea rcx,[rel wnd_class]
    API RegisterClassW

    lea rdi,[rsp+32]
    xor eax,eax
    push byte 8
    pop rcx
    rep stosq
    mov dword [rsp+32],0x80000000
    mov dword [rsp+48],0x80000000
    xor ecx,ecx
    lea rdx,[rel w_title]
    mov r8,rdx
    mov r9d,0x00CF0000
    API CreateWindowExW
    mov rcx,rax
    API GetDC
    mov G(window_dc),rax
    mov rcx,rax
    push byte 88
    pop rdx
    API GetDeviceCaps
    cvtsi2ss xmm0,eax
    mulss xmm0,C(c_inv96)
    movss G(ui_scale),xmm0



    call initialize_renderer
    call update_theme
    mov rcx,G(window_handle)
    xor edx,edx
    push byte 10
    pop r8
    xor r9d,r9d
    API SetTimer
    mov rcx,G(window_handle)
    push byte 10
    pop rdx
    API ShowWindow
.message_loop:
    lea rcx,[rel message_buffer]
    xor edx,edx
    xor r8d,r8d
    xor r9d,r9d
    API GetMessageW
    test eax,eax
    jle .exit
    lea rcx,[rel message_buffer]
    API DispatchMessageW
    jmp .message_loop
.exit:
    xor ecx,ecx
    API ExitProcess

navigation_pop_history:
    sub rsp,40
    mov rax,G(navigation_history)
    mov rcx,[rax+H_ROOT]
    mov G(display_root),rcx
    mov rcx,[rax+H_PREV]
    mov G(navigation_history),rcx
    mov rcx,rax
    call heap_free
    add rsp,40
    ret

animation_begin_back:
    mov rax,G(navigation_history)
    test rax,rax
    jz .done
    movups xmm0,G(current_view)
    movups G(animation_from),xmm0
    movups xmm0,[rax+H_VIEW]
    movups G(animation_to),xmm0
    xor eax,eax
    mov G(animation_progress),eax
    mov byte G(animation_back),1
    mov byte G(animation_active),1
.done:
    ret

animation_begin_forward:
    push rsi
    sub rsp,32
    mov rsi,G(display_root)
    push byte H_BYTES
    pop rcx
    call heap_alloc_zeroed
    mov [rax+H_ROOT],rsi
    movups xmm0,G(current_view)
    movups [rax+H_VIEW],xmm0
    mov rcx,G(navigation_history)
    mov [rax+H_PREV],rcx
    mov G(navigation_history),rax
    movups G(animation_from),xmm0
    movups xmm0,C(default_view)
    movups G(animation_to),xmm0
    mov rax,G(hovered_node)
    mov G(display_root),rax
    xor eax,eax
    mov G(animation_progress),eax
    mov byte G(animation_active),1
    add rsp,32
    pop rsi
.done:
    ret

; RAX=node, ST0 <- the completed or currently published scan size.
node_visible_size:
    fld dword [rax+N_FLOAT]
    ret

; XMM0 is elapsed seconds. Only navigation uses cosine interpolation.
animation_tick:
    push rsi
    push rdi
    sub rsp,56
    movss [rsp+48],xmm0
    call state_lock
    fld dword [rsp+48]
    fadd st0,st0
    fadd dword G(animation_progress)
    fstp dword G(animation_progress)
    movss xmm0,dword G(animation_progress)
    comiss xmm0,C(c_one)
    jb .interpolate
    movups xmm0,C(default_view)
    cmp dword G(animation_back),0
    je .not_back
    movups G(current_view),xmm0
    call navigation_pop_history
    jmp .finished
.not_back:
    movups xmm0,G(animation_to)
    movups G(current_view),xmm0
.finished:
    mov byte G(animation_back),0
    mov byte G(animation_active),0
    jmp .redraw
.interpolate:
    fld dword G(animation_progress)
    fmul dword C(c_pi)
    fcos
    fsubr dword C(c_one)
    fmul dword C(c_half)
    fstp dword [rsp+48]
    lea rsi,G(animation_from)
    lea rdi,G(animation_to)
    lea r10,G(current_view)
    push byte 4
    pop rcx
.field:
    fld dword [rdi]
    fsub dword [rsi]
    fmul dword [rsp+48]
    fadd dword [rsi]
    fstp dword [r10]
    add rsi,4
    add rdi,4
    add r10,4
    loop .field
.redraw:
    call update_hover
    call state_unlock
    call render_and_swap
    add rsp,56
    pop rdi
    pop rsi
    ret

; Polar hit test mirroring the renderer's stored single-precision spans.
hit_test_tree:
    push rsi
    push rdi
    sub rsp,72
    mov rsi,rcx
    movss xmm0,G(mouse_x)
    subss xmm0,G(view_center_x)
    movss [rsp+52],xmm0
    movss xmm0,G(mouse_y)
    subss xmm0,G(view_center_y)
    movss [rsp+56],xmm0
    fld dword [rsp+52]
    fmul st0,st0
    fld dword [rsp+56]
    fmul st0,st0
    faddp st1
    fsqrt
    fdiv dword G(ui_scale)
    fstp dword [rsp+32]               ; radius
    fld dword [rsp+56]
    fchs
    fld dword [rsp+52]
    fxch st1
    fpatan                            ; atan2(mouse_x,-mouse_y)
    fstp dword [rsp+36]
    movss xmm0,[rsp+36]
    xorps xmm1,xmm1
    comiss xmm0,xmm1
    jae .angle_ready
    fld dword [rsp+36]
    fadd dword C(c_two_pi)
    fstp dword [rsp+36]
.angle_ready:
    movups xmm0,G(current_view)
    movups G(hit_test_layout),xmm0
.node:
    test rsi,rsi
    jz .miss
    movss xmm0,[rsp+32]
    comiss xmm0,G(hit_test_layout+V_INNER)
    jb .miss
    comiss xmm0,G(hit_test_layout+V_OUTER)
    ja .children
    movss xmm0,[rsp+36]
    comiss xmm0,G(hit_test_layout+V_START)
    jb .miss
    movss xmm1,G(hit_test_layout+V_START)
    addss xmm1,G(hit_test_layout+V_SWEEP)
    comiss xmm0,xmm1
    ja .miss
    mov rax,rsi
    jmp .return
.children:
    movss xmm0,G(hit_test_layout+V_OUTER)
    addss xmm0,C(c_ring_width)
    comiss xmm0,G(view_radius)
    ja .miss
    mov rax,rsi
    call node_visible_size
    fstp dword [rsp+40]
    mov rdi,[rsi+N_CHILD]
    test rdi,rdi
    jz .miss
    mov eax,G(hit_test_layout+V_START)
    mov [rsp+44],eax                  ; angular cursor
.child:
    mov rax,rdi
    call node_visible_size
    fdiv dword [rsp+40]
    fmul dword G(hit_test_layout+V_SWEEP)
    fstp dword [rsp+48]
    fld dword G(hit_test_layout+V_OUTER)
    fadd dword C(c_ring_width)
    fmul dword [rsp+48]
    fcomp dword C(c_three)
    fnstsw ax
    test ah,0x41
    jnz .skip_child
    movss xmm0,[rsp+36]
    comiss xmm0,[rsp+44]
    jb .next_child
    movss xmm1,[rsp+44]
    addss xmm1,[rsp+48]
    comiss xmm0,xmm1
    jbe .selected
.next_child:
    fld dword [rsp+44]
    fadd dword [rsp+48]
    fstp dword [rsp+44]
.skip_child:
    mov rdi,[rdi+N_NEXT]
    test rdi,rdi
    jnz .child
    jmp .miss
.selected:
    mov eax,G(hit_test_layout+V_OUTER)
    mov G(hit_test_layout+V_INNER),eax
    fld dword G(hit_test_layout+V_OUTER)
    fadd dword C(c_ring_width)
    fstp dword G(hit_test_layout+V_OUTER)
    mov eax,[rsp+44]
    mov G(hit_test_layout+V_START),eax
    mov eax,[rsp+48]
    mov G(hit_test_layout+V_SWEEP),eax
    mov rsi,rdi
    jmp .node
.miss:
    xor eax,eax
.return:
    add rsp,72
    pop rdi
    pop rsi
    ret

update_hover:
    push rsi
    sub rsp,32
    cmp dword G(scan_active),0
    jne .cursor
    mov rsi,G(hovered_node)
    call hit_test_scene
    mov G(hovered_node),rax
    cmp dword G(animation_active),0
    jne .cursor
    cmp rsi,rax
    je .cursor
    call render_and_swap
.cursor:
    mov rcx,G(arrow_cursor)
    cmp qword G(hovered_node),0
    je .set
    mov rcx,G(hand_cursor)
.set:
    API SetCursor
    add rsp,32
    pop rsi
    ret

; ECX=WM_LBUTTONDOWN flags. Plain clicks re-root folders; Ctrl+click locates any item.
handle_left_click:
    push rsi
    push r12
    sub rsp,56
    mov esi,ecx
    call state_lock
    cmp dword G(scan_active),0
    jne .unlock
    mov r12,G(hovered_node)
    test r12,r12
    jz .unlock
    test sil,8                     ; MK_CONTROL belongs to this particular click
    jnz .locate
    cmp byte [r12+N_IS_FILE],0
    jne .unlock
    cmp r12,G(display_root)
    je .unlock                     ; clicking the current center keeps it as the root
    call navigate_to_hovered
    jmp .unlock
.locate:
    xor esi,esi
    lea r8,[r12+N_BYTES]
    xor r9d,r9d
    cmp byte [r12+N_IS_FILE],0
    je .execute
    mov rcx,r8
    call wcslen16
    lea ecx,[rax+rax+22]
    call heap_alloc_zeroed
    mov rsi,rax
    mov rcx,rax
    lea rdx,[rel w_select_format]
    lea r8,[r12+N_BYTES]
    API wsprintfW
    lea r8,[rel w_explorer]
    mov r9,rsi
.execute:
    call shell_execute
    test rsi,rsi
    jz .unlock
    mov rcx,rsi
    call heap_free
.unlock:
    call state_unlock
    add rsp,56
    pop r12
    pop rsi
    ret

; RCX/RDX and the two stack arguments are shared by both Shell actions.
; This tail wrapper uses the caller's already reserved six-argument call area.
shell_execute:
    xor ecx,ecx
    xor edx,edx
    mov [rsp+40],rdx
    mov dword [rsp+48],10
    jmp qword [rel api_table + api_ShellExecuteW]

open_new_scan:
    sub rsp,56
    xor ecx,ecx
    lea rdx,[rel executable_path]
    mov r8d,32768
    API GetModuleFileNameW
    dec eax
    cmp eax,32767                   ; reject zero or a truncated module path
    jae .done
    lea r8,[rel executable_path]
    xor r9d,r9d                     ; no root argument: use the existing picker
    call shell_execute
.done:
    add rsp,56
    ret

; Clone under the tree lock; transfer only a movable, unlocked global handle.
; Any failed allocation/lock/open/empty/set leaves ownership with this function.
copy_current_path:
    push rsi
    push rdi
    push r12
    sub rsp,32
    call state_lock
    mov rsi,G(hovered_node)
    test rsi,rsi
    cmovz rsi,G(display_root)
    test rsi,rsi
    jz .unlock
    mov rax,rsi
    call node_path
    cmp word [rsi+N_BYTES],0
    jne .path_ready
    lea rcx,[rel w_computer_path]
.path_ready:
    mov rsi,rcx
    call wcslen16
    lea edx,[rax+rax+2]
    push byte 2                     ; GMEM_MOVEABLE
    pop rcx
    API GlobalAlloc
    test rax,rax
    jz .unlock
    mov r12,rax
    mov rcx,rax
    API GlobalLock
    test rax,rax
    jz .free
    mov rdi,rax
.copy:
    lodsw
    stosw
    test ax,ax
    jnz .copy
    mov rcx,r12
    API GlobalUnlock
    mov rcx,G(window_handle)
    API OpenClipboard
    test eax,eax
    jz .free
    API EmptyClipboard
    test eax,eax
    jz .close
    push byte 13                    ; CF_UNICODETEXT
    pop rcx
    mov rdx,r12
    API SetClipboardData
    test rax,rax
    jz .close
    xor r12d,r12d                   ; Windows now owns the allocation
.close:
    API CloseClipboard
.free:
    test r12,r12
    jz .unlock
    mov rcx,r12
    API GlobalFree
.unlock:
    call state_unlock
    add rsp,32
    pop r12
    pop rdi
    pop rsi
    ret

navigate_to_hovered:
    sub rsp,40
    call state_lock
    cmp dword G(animation_active),0
    jne .unlock
    cmp dword G(scan_active),0
    jne .unlock
    mov rax,G(hovered_node)
    test rax,rax
    jz .unlock
    cmp rax,G(display_root)
    jne .forward
    call animation_begin_back
    jmp .hover
.forward:
    movups xmm0,G(hit_test_layout)
    movups G(current_view),xmm0
    call animation_begin_forward
.hover:
    call update_hover
.unlock:
    call state_unlock
    add rsp,40
    ret

handle_mouse_move:
    sub rsp,40
    movsx eax,cx
    cvtsi2ss xmm0,eax
    movss dword G(mouse_x),xmm0
    shr ecx,16
    movsx eax,cx
    cvtsi2ss xmm0,eax
    movss dword G(mouse_y),xmm0
    call state_lock
    call update_hover
    call state_unlock
    add rsp,40
    ret

resize_viewport:
    push rsi
    sub rsp,64
    cmp qword G(font_dc),0
    je .done
    xor eax,eax
    mov G(dib_pixels),rax
    mov eax,G(client_width)
    test eax,eax
    jz .done
    mov [rel bitmap_info+4],eax
    mov eax,G(client_height)
    test eax,eax
    jz .done
    neg eax
    mov [rel bitmap_info+8],eax
    mov rcx,G(font_dc)
    lea rdx,[rel bitmap_info]
    xor r8d,r8d
    lea r9,[rsp+48]
    mov [rsp+32],r8
    mov [rsp+40],r8
    API CreateDIBSection
    test rax,rax
    jz .done
    mov rsi,rax
    mov rax,[rsp+48]
    mov G(dib_pixels),rax
    mov rcx,G(font_dc)
    mov rdx,rsi
    API SelectObject
    mov rcx,G(dib_bitmap)
    mov G(dib_bitmap),rsi
    test rcx,rcx
    jz .done
    API DeleteObject
.done:
    add rsp,64
    pop rsi
    ret

invalidate_window:
    mov rcx,G(window_handle)
    xor edx,edx
    xor r8d,r8d
    jmp qword [rel api_table + api_InvalidateRect]

render_and_swap:
    sub rsp,72
    call update_scroll
    cmp qword G(dib_pixels),0
    je .done
    call render_scene
    mov rcx,G(window_dc)
    xor edx,edx
    xor r8d,r8d
    mov r9d,G(client_width)
    mov eax,G(client_height)
    mov [rsp+32],rax
    mov rax,G(font_dc)
    mov [rsp+40],rax
    mov [rsp+48],rdx
    mov [rsp+56],rdx
    mov dword [rsp+64],0x00CC0020
    API BitBlt
    API GdiFlush
.done:
    add rsp,72
    ret

; WNDPROC external entry: RCX=HWND, EDX=message, R8=wParam, R9=lParam.
window_proc:
    push rbx
    push rbp
    push rsi
    push r15
    sub rsp,72
    mov [rsp+32],rcx
    mov [rsp+40],r8
    mov [rsp+48],r9
    mov esi,edx
    LOAD_BASES
    LOAD_CONSTANTS
    mov G(window_handle),rcx         ; creation-time theme messages also have a valid HWND
    mov eax,esi
    cmp eax,0x1A                    ; WM_SETTINGCHANGE
    je .theme
    cmp eax,0x31A                   ; WM_THEMECHANGED
    je .theme
    cmp eax,0x100
    ja .above_key
    je .key
    sub eax,2
    je .exit_process
    sub eax,3
    je .size
    sub eax,10
    je .paint
    dec eax
    je .exit_process
    jmp .default
.above_key:
    sub eax,0x113
    je .timer
    dec eax
    je .scroll
    sub eax,0xEC
    je .mouse_move
    dec eax
    je .left_click
    sub eax,3
    je .right_click
.default:
    mov rcx,[rsp+32]
    mov edx,esi
    mov r8,[rsp+40]
    mov r9,[rsp+48]
    API DefWindowProcW
    jmp .return
.theme:
    call update_theme
    jmp .zero
.exit_process:
    xor ecx,ecx
    API ExitProcess
.size:
    mov eax,[rsp+48]
    movzx ecx,ax
    mov G(client_width),ecx
    shr eax,16
    mov G(client_height),eax
    call resize_viewport
    jmp .zero
.paint:
    mov rcx,[rsp+32]
    xor edx,edx
    API ValidateRect
    ; Only the UI thread owns the framebuffer and initialized drawing state.
    call state_lock
    call update_hover
    call state_unlock
    call render_and_swap
    jmp .zero
.left_click:
    mov ecx,[rsp+48]
    call handle_mouse_move
    mov ecx,[rsp+40]
    call handle_left_click
    jmp .zero
.mouse_move:
    mov ecx,[rsp+48]
    call handle_mouse_move
    jmp .zero
.timer:
    API GetTickCount
    mov [rsp+56],eax
    cmp dword G(scan_active),0
    jne .throttle
    cmp dword G(refresh_requested),0
    je .animate
.throttle:
    inc dword G(redraw_divider)
    cmp dword G(redraw_divider),3
    jne .animate
    call render_and_swap
    xor eax,eax
    mov G(redraw_divider),eax
.animate:
    cmp dword G(animation_active),0
    je .save_tick
    mov eax,[rsp+56]
    sub eax,G(last_tick)
    cvtsi2ss xmm0,rax
    mulss xmm0,C(c_point001)
    call animation_tick
.save_tick:
    mov eax,[rsp+56]
    mov G(last_tick),eax
.zero:
    xor eax,eax
.return:
    add rsp,72
    pop r15
    pop rsi
    pop rbp
    pop rbx
    ret

.scroll:
    mov eax,[rsp+40]
    movzx ecx,ax
    mov edx,G(client_width)
    cmp ecx,4
    jae .absolute
    cmp ecx,2
    jae .direction
    push byte 32
    pop rdx
.direction:
    test cl,1
    jnz .relative
    neg edx
.relative:
    add edx,G(overview_scroll)
    jmp .scroll_to
.absolute:
    shr eax,16
    mov edx,eax
    cmp ecx,5
    jbe .scroll_to
    xor edx,edx
    cmp ecx,6
    je .scroll_to
    dec edx
    shr edx,1
    cmp ecx,7
    jne .zero
.scroll_to:
    mov G(overview_scroll),edx
    call update_scroll
    jmp .paint
.right_click:
    call navigate_to_hovered
    jmp .zero
.key:
    mov eax,[rsp+40]
    cmp eax,0x71                    ; F2: another independent analysis
    je .new_window
    cmp eax,'C'                     ; C (also Ctrl+C): Unicode path
    je .copy_path
    cmp dword G(scan_active),0
    jne .zero
    cmp eax,0x74
    jne .navigation_key
    mov byte G(refresh_requested),1
    jmp .zero
.navigation_key:
    cmp dword G(animation_active),0
    jne .zero
    cmp eax,13
    je .right_click
    cmp eax,36
    je .home
    cmp eax,8
    jne .zero
    mov rax,G(display_root)
    mov G(hovered_node),rax
    jmp .right_click
.home:
    call state_lock
.home_next:
    cmp qword G(navigation_history),0
    je .home_ready
    call navigation_pop_history
    jmp .home_next
.home_ready:
    movups xmm0,C(default_view)
    movups G(current_view),xmm0
    call update_hover
    call state_unlock
    call render_and_swap
    jmp .zero
.new_window:
    call open_new_scan
    jmp .zero
.copy_path:
    call copy_current_path
    jmp .zero
; Follow the per-user application theme; missing or invalid values mean light.
; The documented DWM attribute is harmless on systems that do not support it.
update_theme:
    sub rsp,72
    mov dword [rsp+60],4
    mov rcx,-2147483647             ; sign-extended HKEY_CURRENT_USER
    lea rdx,[rel theme_key]
    lea r8,[rel theme_value]
    push byte 24                   ; RRF_RT_REG_DWORD
    pop r9
    xor eax,eax
    mov [rsp+32],rax
    lea rax,[rsp+56]
    mov [rsp+40],rax
    lea rax,[rsp+60]
    mov [rsp+48],rax
    API RegGetValueA
    xor ecx,ecx
    test eax,eax
    jnz .value
    cmp dword [rsp+56],0
    sete cl
.value:
    mov G(theme_dark),ecx
    mov rcx,G(window_handle)
    push byte 20                   ; DWMWA_USE_IMMERSIVE_DARK_MODE
    pop rdx
    lea r8,G(theme_dark)
    push byte 4
    pop r9
    API DwmSetWindowAttribute
    add rsp,72
    jmp invalidate_window

; Native GDI+ draws smooth geometry into the same DIB used for GDI text.
initialize_renderer:
    push rsi
    sub rsp,64
    mov byte [rel gp_startup],1
    lea rcx,[rel gp_token]
    lea rdx,[rel gp_startup]
    xor r8d,r8d
    API GdiplusStartup
    mov ecx,0xFF000000
    movss xmm1,C(c_one)
    push byte 2
    pop r8
    lea r9,G(outline_pen)
    API GdipCreatePen1
    mov ecx,0xFF000000
    lea rdx,G(fill_brush)
    API GdipCreateSolidFill
    push byte 31
    pop rcx
    push byte 92
    pop rdx
    lea r8,[rel log_font]
    xor r9d,r9d
    API SystemParametersInfoW
    lea rcx,[rel log_font]
    API CreateFontIndirectW
    mov rsi,rax
    xor ecx,ecx
    API CreateCompatibleDC
    mov G(font_dc),rax
    mov rcx,rax
    mov rdx,rsi
    API SelectObject
    mov rcx,G(font_dc)
    push byte 1
    pop rdx
    API SetBkMode
    lea rcx,[rel w_scanning]
    lea rdx,[rsp+40]
    call measure_text
    mov G(font_height),eax
    call resize_viewport
    add rsp,64
    pop rsi
    ret

measure_text:
    mov r9,rdx
    xorps xmm0,xmm0
    movups [r9],xmm0
    mov rdx,rcx
    mov dword [rsp+40],0xC00
font_text:
    mov rcx,G(font_dc)
    push byte -1
    pop r8
    jmp qword [rel api_table + api_DrawTextW]

draw_centered_text:
    push byte 1
    pop rdx
    jmp text_label
draw_text:
    xor edx,edx
text_label:
    push rsi
    push rdi
    sub rsp,72
    mov rsi,rcx
    mov edi,edx
    lea rdx,[rsp+48]
    call measure_text
    mov eax,[rsp+56]
    mov [rsp+40],eax
    cvtss2si ecx,G(render_x)
    mov edx,G(client_height)
    cvtss2si r8d,G(render_y)
    sub edx,r8d
    mov r8d,[rsp+60]
    test edi,edi
    jz .left
    sar eax,1
    sub ecx,eax
    sar r8d,1
    sub edx,r8d
    jmp .rect
.left:
    sub edx,G(font_height)
.rect:
    mov [rsp+48],ecx
    mov [rsp+52],edx
    add [rsp+56],ecx
    add [rsp+60],edx
    xor edx,edx
    test edi,edi
    jnz .color
    mov edx,G(theme_dark)
    neg edx
    shr edx,8
.color:
    mov rcx,G(font_dc)
    API SetTextColor
    mov rdx,rsi
    lea r9,[rsp+48]
    mov dword [rsp+32],0x800
    call font_text
    cvtsi2ss xmm0,dword [rsp+40]
    addss xmm0,G(render_x)
    movss G(render_x),xmm0
    add rsp,72
    pop rdi
    pop rsi
    ret

draw_reset_origin:
    xor eax,eax
    mov G(render_x),rax
    ret
draw_translate_origin:
    addss xmm0,G(render_x)
    addss xmm1,G(render_y)
    movss G(render_x),xmm0
    movss G(render_y),xmm1
    ret



; XMM0=size in bytes. The original format and unsigned argument behavior are retained.
draw_size_label:
    sub rsp,72
    movss [rsp+48],xmm0
    xor r10d,r10d
    fld dword [rsp+48]
.scale:
    fdiv dword C(size_thresholds)
    fst dword [rsp+52]
    movss xmm0,[rsp+52]
    comiss xmm0,C(size_thresholds)
    jb .rounded
    inc r10d
    jmp .scale
.rounded:
    fmul dword C(c_hundred)
    fistp dword [rsp+52]
    mov eax,[rsp+52]
    xor edx,edx
    push byte 100
    pop rcx
    div ecx
    lea r11,[rel size_units]
    movzx r11d,byte [r11+r10]
    mov [rsp+32],r11
    mov r8d,eax
    mov r9d,edx
    xor eax,eax
    mov [rsp+40],rax                 ; empty roots have 0%, with no division
    mov rax,G(chart_root)
    call node_visible_size
    fstp dword [rsp+56]
    cmp dword [rsp+56],0
    je .format
    fld dword [rsp+48]
    fdiv dword [rsp+56]
    fmul dword C(c_hundred)
    fistp dword [rsp+40]
.format:
    lea rcx,[rel size_text_buffer]
    lea rdx,[rel w_size_format]
    API wsprintfW
    lea rcx,[rel size_text_buffer]
    call draw_centered_text
    add rsp,72
    ret

; RCX=annular span. GDI+ supplies antialiasing and the one-pixel black contour.
draw_sector:
    push rsi
    push rdi
    sub rsp,56
    mov rsi,rcx
    xor ecx,ecx
    lea rdx,[rsp+40]
    API GdipCreatePath
    test eax,eax
    jnz .done
    mov rdi,[rsp+40]
    xor edx,edx
    call sector_arc
    cmp dword [rsi+V_INNER],0
    je .close
    movss xmm0,[rsi+V_SWEEP]
    comiss xmm0,C(c_two_pi_low)
    jb .inner
    mov rcx,rdi
    API GdipStartPathFigure
.inner:
    push byte 1
    pop rdx
    call sector_arc
.close:
    mov rcx,rdi
    API GdipClosePathFigure
    mov rcx,G(graphics)
    mov rdx,G(fill_brush)
    mov r8,rdi
    API GdipFillPath
    mov rcx,G(graphics)
    mov rdx,G(outline_pen)
    mov r8,rdi
    API GdipDrawPath
    mov rcx,rdi
    API GdipDeletePath
.done:
    add rsp,56
    pop rdi
    pop rsi
    ret

; RSI=span, RDI=path, EDX=inner contour. GDI+ angles use degrees from the right.
sector_arc:
    sub rsp,72
    movss xmm0,[rsi+V_OUTER]
    test edx,edx
    jz .radius
    movss xmm0,[rsi+V_INNER]
.radius:
    mulss xmm0,G(ui_scale)
    movss xmm1,G(render_x)
    subss xmm1,xmm0
    cvtsi2ss xmm2,dword G(client_height)
    subss xmm2,G(render_y)
    subss xmm2,xmm0
    movaps xmm3,xmm0
    addss xmm3,xmm3
    movss [rsp+32],xmm3
    fld dword [rsi+V_START]
    test edx,edx
    jz .angle
    fadd dword [rsi+V_SWEEP]
.angle:
    fmul dword C(c_degrees)
    fsub dword C(c_ninety)
    fstp dword [rsp+40]
    fld dword [rsi+V_SWEEP]
    fmul dword C(c_degrees)
    test edx,edx
    jz .sweep
    fchs
.sweep:
    fstp dword [rsp+48]
    mov rcx,rdi
    API GdipAddPathArc
    add rsp,72
    ret


; RCX=node, RDX=mutable span. Native paths combine the fill and outline.
draw_tree:
    push rsi
    push rdi
    push r14
    sub rsp,64
    mov rsi,rcx
    mov rdi,rdx
    mov eax,[rdi+V_START]
    mov [rsp+60],eax                 ; per-recursion angular cursor
    xor eax,eax
    cmp rsi,G(hovered_node)
    jne .kind
    push byte 3
    pop rax
    jmp .scan_color
.kind:
    cmp byte [rsi+N_IS_FILE],0
    sete al
    inc eax
.scan_color:
    cmp dword G(scan_active),0
    je .color
    add eax,4
.color:
    imul eax,eax,3
    lea rcx,C(color_palette)
    mov edx,[rcx+rax]
    bswap edx
    shr edx,8
    or edx,0xFF000000
    mov rcx,G(fill_brush)
    API GdipSetSolidFillColor
    mov rcx,rdi
    call draw_sector
.descend:
    movss xmm0,[rdi+V_OUTER]
    addss xmm0,C(c_ring_width)
    comiss xmm0,dword G(view_radius)
    ja .done
    mov rax,rsi
    call node_visible_size
    fstp dword [rsp+32]
    cmp dword [rsp+32],0            ; keep the center bubble for empty scans, without 0/0
    je .done
    mov r14,[rsi+N_CHILD]
    test r14,r14
    jz .done
.child:
    mov eax,[rdi+V_OUTER]
    mov [rsp+40+V_INNER],eax
    fld dword [rdi+V_OUTER]
    fadd dword C(c_ring_width)
    fstp dword [rsp+40+V_OUTER]
    mov eax,[rsp+60]
    mov [rsp+40+V_START],eax
    mov rax,r14
    call node_visible_size
    fdiv dword [rsp+32]
    fmul dword [rdi+V_SWEEP]
    fstp dword [rsp+40+V_SWEEP]
    fld dword [rsp+40+V_OUTER]
    fmul dword [rsp+40+V_SWEEP]
    fcomp dword C(c_three)
    fnstsw ax
    test ah,0x41
    ; Match the original: collapse sub-three-pixel children instead of
    ; advancing the cursor and leaving an unpaired radial edge.
    jnz .next_child
    mov rcx,r14
    lea rdx,[rsp+40]
    call draw_tree
.advance:
    fld dword [rsp+60]
    fadd dword [rsp+40+V_SWEEP]
    fstp dword [rsp+60]
.next_child:
    mov r14,[r14+N_NEXT]
    test r14,r14
    jnz .child
.done:
    add rsp,64
    pop r14
    pop rdi
    pop rsi
    ret

render_scene:
    push rsi
    push rdi
    push r12
    push r13
    sub rsp,88
    cmp qword G(dib_pixels),0
    je .return
    API GdiFlush
    mov rdi,G(dib_pixels)
    mov ecx,G(client_width)
    imul ecx,G(client_height)
    mov eax,0xFFFFFF
    cmp byte G(theme_dark),0
    je .clear
    mov eax,0x202020
.clear:
    rep stosd
    ; Load all tree pointers under the lock: refresh can replace and free the old tree.
    call state_lock
    mov r12,G(display_root)
    test r12,r12
    jz .unlock
    call chart_begin
    mov r13,rax
.chart:
    test r13,r13
    jz .hint
    mov rcx,G(font_dc)
    lea rdx,G(graphics)
    API GdipCreateFromHDC
    test eax,eax
    jnz .hint
    mov rcx,G(graphics)
    push byte 4
    pop rdx
    API GdipSetSmoothingMode
    call draw_reset_origin
    movss xmm0,dword G(view_center_x)
    movss xmm1,dword G(view_center_y)
    call draw_translate_origin
    movups xmm0,G(current_view)
    movups [rsp+48],xmm0
    mov rcx,r13
    lea rdx,[rsp+48]
    call draw_tree
    mov rcx,G(graphics)
    API GdipDeleteGraphics
    movss xmm0,C(c_neg_half)
    movaps xmm1,xmm0
    call draw_translate_origin
    cmp dword G(scan_active),0
    je .size
    lea rcx,[rel w_scanning]
    call draw_centered_text
    jmp .drive_label
.size:
    cmp qword [r13+F_HANDLE],-1
    jne .available
    lea rcx,[rel w_unavailable]
    call draw_centered_text
    jmp .drive_label
.available:
    mov rax,r13
    cmp r13,G(hover_chart)
    jne .size_node
    mov rax,G(hovered_node)
    test rax,rax
    cmovz rax,r13
.size_node:
    call node_visible_size
    fstp dword [rsp+36]
    movss xmm0,[rsp+36]
    call draw_size_label
.drive_label:
    cmp dword G(chart_overview),0
    je .next_chart
    call draw_reset_origin
    movss xmm0,G(view_center_x)
    movss xmm1,G(view_center_y)
    cvtsi2ss xmm2,dword G(font_height)
    addss xmm1,xmm2
    call draw_translate_origin
    mov rax,r13
    call node_path
    call draw_centered_text
.next_chart:
    mov rcx,r13
    call chart_next
    mov r13,rax
    jmp .chart
.hint:
    cmp dword G(scan_active),0
    jne .path_line
    mov rsi,G(hovered_node)
    test rsi,rsi
    jz .path_line
    call draw_reset_origin
    movss xmm0,C(c_ten)
    cvtsi2ss xmm1,dword G(font_height)
    addss xmm1,C(c_nine)
    call draw_translate_origin
    cmp rsi,r12
    je .back_hint
    lea rcx,[rel w_expand_hint]
    call draw_text
    jmp .path_line
.back_hint:
    cmp dword G(animation_active),0
    jne .path_line
    cmp qword G(navigation_history),0
    je .path_line
    lea rcx,[rel w_back_hint]
    call draw_text
.path_line:
    call draw_reset_origin
    movss xmm0,C(c_ten)
    movss xmm1,C(c_eight)
    call draw_translate_origin
    mov rsi,G(hovered_node)
    test rsi,rsi
    jz .scan_path
    lea rdi,[rel w_locate_prefix]
    cmp byte [rsi+N_IS_FILE],0
    jne .draw_path
    lea rdi,[rel w_click_expand]
    jmp .draw_path
.scan_path:
    mov rax,G(scan_frame_stack)
    test rax,rax
    jz .root_path
    mov rsi,rax
    lea rdi,[rel w_scanning_prefix]
    jmp .draw_path
.root_path:
    mov rsi,r12
    lea rdi,[rel w_scan_of_prefix]
.draw_path:
    mov rcx,rdi
    call draw_text
    mov rax,rsi
    call node_path
    call draw_text
    cmp dword G(scan_active),0
    jne .unlock
    call draw_reset_origin
    movss xmm0,C(c_ten)
    mov eax,G(client_height)
    sub eax,G(font_height)
    cvtsi2ss xmm1,eax
    subss xmm1,C(c_eight)
    call draw_translate_origin
    lea rcx,[rel w_refreshing]
    cmp dword G(refresh_requested),0
    jne .bottom
    lea rcx,[rel w_refresh_hint]
.bottom:
    call draw_text
.unlock:
    call state_unlock
.return:
    add rsp,88
    pop r13
    pop r12
    pop rdi
    pop rsi
    ret

; Allocate a zeroed node followed by "base\child\" (child may be null).
; RAX returns the path (node + N_BYTES), RDX its terminating-null cursor. Callers trim
; directly at the cursor; each node owns its header and path in one allocation.
make_node_path:
    xor eax,eax
make_node_path_cached:
    push rsi
    push rdi
    push r12
    push r13
    sub rsp,40
    mov rsi,rcx
    mov [rsp+32],rdx
    mov r12d,eax
    test eax,eax
    jnz .base_length_ready
    call wcslen16
    mov r12d,eax
.base_length_ready:
    mov r13d,r8d
.lengths_ready:
    lea ecx,[r12+r13+4+N_BYTES/2]
    add ecx,ecx
    call heap_alloc_zeroed
    lea r11,[rax+N_BYTES]
    mov rdi,r11
    mov rcx,r12
    rep movsw
    test r12d,r12d
    jz .copy_child
    cmp word [rdi-2],'\'
    je .copy_child
    mov word [rdi],'\'
    add rdi,2
.copy_child:
    test r13d,r13d
    jz .path_end
    mov rsi,[rsp+32]
    mov ecx,r13d
    rep movsw
    ; Counted directory-record names are basenames without a separator.
    mov word [rdi],'\'
    add rdi,2
.path_end:
    mov rdx,rdi
    mov rax,r11
    add rsp,40
    pop r13
    pop r12
    pop rdi
    pop rsi
    ret

free_node_list:
    push rsi
    push rdi
    sub rsp,40
    mov rsi,rcx
.node:
    test rsi,rsi
    jz .done
    mov rdi,rsi
    mov rsi,[rsi+N_NEXT]
    mov rcx,[rdi+N_CHILD]
    call free_node_list
    mov rcx,rdi
    call heap_free
    jmp .node
.done:
    add rsp,40
    pop rdi
    pop rsi
    ret

 ; RCX=base path, RDX=counted child, R8D=child characters (zero for root).
scan_frame_create:
    push rsi
    sub rsp,64
    call make_node_path
    lea rsi,[rax-N_BYTES]
    sub rdx,rax
    shr edx,1
    mov [rsi+N_PATHLEN],dx
    mov rcx,rax
    push byte 1
    pop rdx                         ; FILE_LIST_DIRECTORY
    push byte 7
    pop r8                          ; share read/write/delete
    xor r9d,r9d
    mov dword [rsp+32],3             ; OPEN_EXISTING
    mov dword [rsp+40],0x02000000    ; FILE_FLAG_BACKUP_SEMANTICS, synchronous
    mov [rsp+48],r9
    API CreateFileW
    mov [rsi+F_HANDLE],rax
    cmp rax,-1
    je .return
    mov ecx,ENUM_BYTES+B_DATA
    call heap_alloc_zeroed
    mov [rsi+F_BUFFER],rax
.return:
    mov rax,rsi
    add rsp,64
    pop rsi
    ret

scan_directory_tree:
    push rsi
    push rdi
    push r12
    push r13
    push r14
    sub rsp,96
    mov r13,rcx
.top:
    mov rsi,[r13]
    cmp rsi,[r13+8]
    je .done
    cmp qword [rsi+F_HANDLE],-1
    je .pop
    mov r14,[rsi+F_BUFFER]
    mov r14,[r14+B_CURSOR]
    test r14,r14
    jz .refill
    add r14,64
    cmp word [r14],'.'
    jne .attributes
    cmp dword [r14-4],2
    je .advance
    cmp word [r14+2],'.'
    jne .attributes
    cmp dword [r14-4],4
    je .advance
.attributes:
    mov edi,[r14-8]
    test dil,0x10
    jz .file
    test edi,0x400
    jnz .advance
    call scan_flush
    lea rcx,[rsi+N_BYTES]
    mov rdx,r14
    mov r8d,[r14-4]
    shr r8d,1
    call scan_frame_create
    mov rdi,rax
    cmp qword [rax+F_HANDLE],-1
    je .bad_directory
.publish_directory:
    call state_lock
    mov rcx,[rsi+N_CHILD]
    mov [rdi+N_NEXT],rcx
    mov [rsi+N_CHILD],rdi
    mov [rdi+F_PARENT],rsi
%if THREAD_WORKERS > 1
    ; Another buffered parent entry proves independent work remains.
    cmp dword [r14-64],0
    je .push
    ; Only the coordinator donates; helpers retain their private subtrees.
    cmp qword [r13+8],0
    jne .push
    lea r12,[rel helper_context]
    push byte THREAD_WORKERS-1
    pop rcx
.find_slot:
    cmp qword [r12+8],0
    je .slot
    add r12,40
    loop .find_slot
    jmp .push
.slot:
    mov [r12],rdi
    mov [r12+8],rsi
    lea rcx,[rel helper_callback]
    mov rdx,r12
    xor r8d,r8d
    API QueueUserWorkItem
    test eax,eax
    jz .submit_failed
    call state_unlock
    jmp .advance
.submit_failed:
    xor eax,eax                      ; BOOL defines EAX, not the upper half of RAX
    mov [r12+8],rax
.push:
%endif
    mov [r13],rdi
    call state_unlock
    jmp .top
.bad_directory:
    cmp qword [rsi+F_HANDLE],0
    je .publish_directory
    ; The unpublished node owns its inline path and has no children or handle.
    mov rcx,rdi
    call heap_free
    jmp .advance

.file:
    mov r12,[r14-24]
    lea rcx,[rsi+N_BYTES]
    mov rdx,r14
    movzx eax,word [rsi+N_PATHLEN]
    mov r8d,[r14-4]
    shr r8d,1
    call make_node_path_cached
    mov word [rdx-2],0
    lea rdi,[rax-N_BYTES]
    mov [rdi+N_SIZE],r12
    mov byte [rdi+N_IS_FILE],1
    mov rcx,rdi
    call uint64_to_float
    mov rcx,[r13+C_HEAD]
    cmp dword [r13+C_COUNT],0
    jne .link_file
    mov rcx,[rsi+N_CHILD]
.link_file:
    mov [rdi+N_NEXT],rcx
    mov [r13+C_HEAD],rdi
    add [r13+C_DELTA],r12
    inc dword [r13+C_COUNT]
%if SCAN_BATCH < 256
    ; The low byte contains the complete count before this threshold resets it.
    cmp byte [r13+C_COUNT],SCAN_BATCH
%else
    cmp dword [r13+C_COUNT],SCAN_BATCH
%endif
    jb .advance
    call scan_flush

.advance:
    mov rax,[rsi+F_BUFFER]
    mov rdx,[rax+B_CURSOR]
    mov ecx,[rdx]
    add rdx,rcx
    mov [rax+B_CURSOR],rdx
    test ecx,ecx
    jnz .top
.refill:
    cmp qword [rsi+F_HANDLE],0
    je .pop
    mov rax,[rsi+F_BUFFER]
    lea rdx,[rax+B_DATA]
    mov [rax+B_CURSOR],rdx
    mov [rsp+40],rdx
    lea rdx,[rax+B_IOSTATUS]
    mov [rsp+32],rdx
    mov dword [rsp+48],ENUM_BYTES
    mov dword [rsp+56],1             ; FileDirectoryInformation
    xor edx,edx
    mov [rsp+64],rdx                 ; return multiple entries
    mov [rsp+72],rdx                 ; no filename filter
    mov [rsp+80],rdx                 ; first query automatically restarts
    xor r8d,r8d
    xor r9d,r9d
    mov rcx,[rsi+F_HANDLE]
    API NtQueryDirectoryFile
    test eax,eax
    jnz .pop
    mov rax,[rsi+F_BUFFER]
    cmp qword [rax+B_IOSTATUS+8],0
    jne .top
.pop:
    call scan_flush
%if THREAD_WORKERS > 1
    ; Join every helper borrowing this parent, outside the state lock.
    lea rdx,[rel helper_context]
    push byte THREAD_WORKERS-1
    pop rcx
.join_slot:
    cmp rsi,[rdx+8]
    jne .next_slot
    xor ecx,ecx
    API Sleep
    jmp .pop
.next_slot:
    add rdx,40
    loop .join_slot
%endif
    ; Rendering reads the live frame chain under the same recursive lock.
    call state_lock
    mov rax,[rsi+F_PARENT]
    mov [r13],rax
    call state_unlock
    mov rcx,[rsi+F_HANDLE]
    test rcx,rcx
    jz .free_buffer
    cmp rcx,-1
    je .free_buffer
    API CloseHandle
.free_buffer:
    mov rcx,[rsi+F_BUFFER]
    call heap_free
    mov rsi,[r13]
    cmp rsi,[r13+8]
    jne .advance
.done:
    add rsp,96
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    ret

; Internal convention: RSI=directory, R13=worker; clobbers RDI/R12.
; Children and their exact byte delta become visible together under one lock.
scan_flush:
    cmp dword [r13+C_COUNT],0
    je .done
    sub rsp,40
    call state_lock
    mov rax,[r13+C_HEAD]
    mov [rsi+N_CHILD],rax
    mov r12,[r13+C_DELTA]
    mov rdi,rsi
.accumulate:
    mov rcx,rdi
    add [rcx+N_SIZE],r12
    call uint64_to_float
    mov rdi,[rdi+F_PARENT]
    test rdi,rdi
    jnz .accumulate
    xor eax,eax
    mov [r13+C_DELTA],rax
    mov [r13+C_COUNT],eax
    call state_unlock
    add rsp,40
.done:
    ret

%if THREAD_WORKERS > 1
; A pool callback returns to Windows, so it must restore all nonvolatile bases.
helper_callback:
    push rbx
    push rbp
    push r15
    push rsi
    sub rsp,40
    mov rsi,rcx
    LOAD_BASES
    LOAD_CONSTANTS
    call scan_directory_tree
    xor eax,eax
    mov [rsi+8],rax
    add rsp,40
    pop rsi
    pop r15
    pop rbp
    pop rbx
    ret
%endif

; Use a virtual directory containing native-shaped records for the drive roots.
; The existing worker pool then schedules drives and joins them exactly like folders.
scan_root_create:
    cmp byte G(computer_mode),0
    je scan_frame_create
    push rsi
    push rdi
    push r12
    push r13
    sub rsp,40
    mov ecx,N_BYTES+2
    call heap_alloc_zeroed
    mov rsi,rax
    mov ecx,B_DATA+26*72
    call heap_alloc_zeroed
    mov [rsi+F_BUFFER],rax
    lea rdi,[rax+B_DATA]
    API GetLogicalDrives
    and eax,0x03FFFFFF
    mov r12d,eax
    jz .done
    mov rax,[rsi+F_BUFFER]
    mov [rax+B_CURSOR],rdi
.drive:
    bsr r13d,r12d
    btr r12d,r13d
    mov dword [rdi],72
    mov dword [rdi+56],0x10
    mov dword [rdi+60],4
    add r13d,'A'
    mov [rdi+64],r13w
    mov word [rdi+66],':'
    inc word [rsi+N_PATHLEN]        ; virtual root stores its drive count here
    add rdi,72
    test r12d,r12d
    jnz .drive
    mov dword [rdi-72],0
.done:
    mov rax,rsi
    add rsp,40
    pop r13
    pop r12
    pop rdi
    pop rsi
    ret

; A single shared layout supplies drawing and hit testing with identical centers.
chart_begin:
    mov rax,G(display_root)
    xor ecx,ecx
    mov G(chart_overview),ecx
    inc ecx
    cmp byte G(computer_mode),0
    je .layout
    cmp rax,G(scan_tree_root)
    jne .layout
    mov G(chart_overview),ecx
    movzx ecx,word [rax+N_PATHLEN]
    test ecx,ecx
    jnz .roots
    inc ecx
    jmp .layout
.roots:
    mov rax,[rax+N_CHILD]
.layout:
    cvtsi2ss xmm0,dword G(client_width)
    cvtsi2ss xmm1,ecx
    divss xmm0,xmm1
    cmp dword G(chart_overview),0
    je .step
    movss xmm1,C(c_min_chart)
    mulss xmm1,G(ui_scale)
    maxss xmm0,xmm1
.step:
    movss G(chart_step),xmm0
    mulss xmm0,C(c_half)
    movss G(view_center_x),xmm0
    cvtsi2ss xmm1,dword G(client_height)
    mulss xmm1,C(c_half)
    movss G(view_center_y),xmm1
    minss xmm0,xmm1
    divss xmm0,G(ui_scale)
    movss G(view_radius),xmm0
    cmp dword G(chart_overview),0
    je .root
    cvtsi2ss xmm0,dword G(overview_scroll)
    movss xmm1,G(view_center_x)
    subss xmm1,xmm0
    movss G(view_center_x),xmm1
.root:
    mov G(chart_root),rax
    ret

; Update the standard horizontal scrollbar before painting; changing its visibility
; can synchronously resize the client and replace the DIB.
update_scroll:
    sub rsp,72
    call state_lock
    call chart_begin
    cvtsi2ss xmm0,ecx
    mulss xmm0,G(chart_step)
    cvtss2si eax,xmm0
    dec eax
    mov [rsp+44],eax
    xor eax,eax
    mov [rsp+40],eax
    mov [rsp+52],eax
    cmp G(chart_overview),eax
    je .info
    mov eax,G(overview_scroll)
    mov [rsp+52],eax
.info:
    call state_unlock
    mov dword [rsp+32],28
    mov dword [rsp+36],7
    mov eax,G(client_width)
    mov [rsp+48],eax
    mov rcx,G(window_handle)
    xor edx,edx
    lea r8,[rsp+32]
    push byte 1
    pop r9
    API SetScrollInfo
    cmp dword G(chart_overview),0
    je .done
    mov G(overview_scroll),eax
.done:
    add rsp,72
    ret

; RCX=current chart. A focused folder has no following chart, even if it has siblings.
chart_next:
    xor eax,eax
    cmp dword G(chart_overview),0
    je .done
    mov rax,[rcx+N_NEXT]
    movss xmm0,G(view_center_x)
    addss xmm0,G(chart_step)
    movss G(view_center_x),xmm0
.done:
    mov G(chart_root),rax
    ret

hit_test_scene:
    push rsi
    sub rsp,32
    call chart_begin
    mov rsi,rax
.chart:
    test rsi,rsi
    jz .done
    mov rcx,rsi
    call hit_test_tree
    test rax,rax
    jnz .done
    mov rcx,rsi
    call chart_next
    mov rsi,rax
    jmp .chart
.done:
    mov G(hover_chart),rsi
    add rsp,32
    pop rsi
    ret

node_path:
    lea rcx,[rax+N_BYTES]
    cmp word [rcx],0
    jne .done
    lea rcx,[rel w_this_pc]
.done:
    ret

scanner_thread_proc:
    sub rsp,56
    LOAD_BASES
    LOAD_CONSTANTS
    lea rcx,[rel scan_frame_stack]
    call scan_directory_tree
    call state_lock
    xor esi,esi
    mov G(scan_active),esi
    call invalidate_window
    call state_unlock
.wait_refresh:
    push byte 50
    pop rcx
    API Sleep
    cmp G(refresh_requested),esi
    je .wait_refresh
    call state_lock
    mov rcx,G(command_line_root)
    xor edx,edx
    xor r8d,r8d
    call scan_root_create
    mov rdi,rax
    mov G(scan_frame_stack),rax
    call state_unlock
    cmp qword [rdi+F_HANDLE],-1
    jne .scan_refresh
    call state_lock
    mov G(scan_frame_stack),rsi
    call state_unlock
    jmp .wait_animation
.scan_refresh:
    lea rcx,[rel scan_frame_stack]
    call scan_directory_tree
.wait_animation:
    call state_lock
    cmp G(animation_active),esi
    je .clear_history
    call state_unlock
    push byte 20
    pop rcx
    API Sleep
    jmp .wait_animation
    ; Discard navigation into the old tree before releasing any node it references.
.clear_history:
    cmp G(navigation_history),rsi
    je .replace
    call navigation_pop_history
    jmp .clear_history
.replace:
    mov rcx,G(scan_tree_root)
    mov G(scan_tree_root),rdi
    mov G(display_root),rdi
    mov G(hovered_node),rsi
    mov G(hover_chart),rsi
    mov G(animation_progress),esi
    movups xmm0,C(default_view)
    movups G(current_view),xmm0
    call free_node_list
    mov G(refresh_requested),esi
    call state_unlock
    call invalidate_window
    jmp .wait_refresh

resolver_records:
    db 10,'GDI32',0
    dd 0x66F33A69,0xFE97A655,0xFE3DA875,0x7CBFBF24,0x89364153,0x5D2C86BD,0x70F69C32,0xF1F6D8E6,0x7805F866,0xEB66A115
    db 14,'GDIPLUS',0
    dd 0x824FA267,0x4A6EBF73,0x871A3BFB,0x3B4E94A8,0xB005A65C,0xBE1D1B64,0x3B7E93DF,0xDD2B6BB0,0x814791A4,0xBD495280,0x15DC29B8,0x9600D972,0x2E8E9CBF,0x3D288C73
    db 23,'USER32',0
    dd 0xBC4F79F4,0xD6C1664C,0x7AC67C03,0xE00412FA,0xCBA6C0E5,0x16F8BA2A,0xC95D4F83,0x84454957,0x25388844,0x5251D687,0xB9A87739,0x690A1717,0x57F6BBF1,0xCC248D43,0x33B11BA0,0x7711DD67,0xEB6CC40A,0x671DBB66,0x499E154A,0xCA077F0F,0x089B753A,0x93296CD3,0xFABF87B2
    db 20,'KERNEL32',0
    dd 0xA80EECAE,0xF791FB23,0x10C32616,0x2500383C,0xA12B930B,0x36EF7386,0x73E2D87E,0x7C0017BB,0xA39C10BA,0xDB2D49B0,0x0FFD97FB,0x016D1E21,0xA46A9B02,0x45B06D8C,0x0C0397EC,0x88A9223C,0xBF608091,0x7CB922F6,0x14C22B19,0xA498EAB6
    db 1,'NTDLL',0
    dd 0x6EF04C50
    db 1,'ADVAPI32',0
    dd 0x64A57266
    db 1,'DWMAPI',0
    dd 0xDB69C805
    db 2,'OLE32',0
    dd 0x8C2E8016,0x844406BD
    db 6,'SHELL32',0
    dd 0x1BE1BB74,0xA8C03C08,0x89836A72,0x7460EA39,0x0DDB402A,0xAF307766

align 8,db 0
bootstrap_iat:
iat_LoadLibraryA:   dq hint_LoadLibraryA - IMAGE_BASE
iat_GetProcAddress: dq hint_GetProcAddress - IMAGE_BASE
    dq 0
bootstrap_iat_end:

import_directory:
    dd 0,0,0,dll_kernel32 - IMAGE_BASE,bootstrap_iat - IMAGE_BASE
    times 5 dd 0
import_directory_end:

; Remaining immutable initialized data. ASCII strings are widened once into BSS.

theme_key:         db 'Software\Microsoft\Windows\CurrentVersion\Themes\Personalize',0
theme_value:       db 'AppsUseLightTheme',0

tail_ascii_strings:
s_this_pc: db 'This PC',0
s_unavailable: db 'Unavailable',0
s_click_expand: db 'Click to root ',0
s_computer_path: db 'shell:MyComputerFolder',0
s_refreshing:       db 'Refreshing...',0
s_refresh_hint:     db 'Click Root',10,'Ctrl+click Locate',10,'F2 New scan',10,'F5 Refresh',10,'Enter Expand',10,'Backspace Back',10,'Home Root',10,'C Copy path',0
s_select_format:    db '/select,"%s"',0
s_size_format:      db '%u.%02u %cB (%u%%)',0
tail_ascii_strings_end:

w_this_pc equ wide_tail_strings + 2*(s_this_pc-tail_ascii_strings)
w_unavailable equ wide_tail_strings + 2*(s_unavailable-tail_ascii_strings)
w_click_expand equ wide_tail_strings + 2*(s_click_expand-tail_ascii_strings)
w_computer_path equ wide_tail_strings + 2*(s_computer_path-tail_ascii_strings)
w_initial_path      equ wide_header_strings + 2*(s_initial_path-header_ascii_strings)
w_title             equ wide_header_strings + 2*(s_title-header_ascii_strings)
w_scanning          equ wide_header_strings + 2*(s_scanning-header_ascii_strings)
w_expand_hint       equ wide_header_strings + 2*(s_expand_hint-header_ascii_strings)
w_back_hint         equ wide_header_strings + 2*(s_back_hint-header_ascii_strings)
w_locate_prefix     equ wide_header_strings + 2*(s_locate_prefix-header_ascii_strings)
w_scanning_prefix   equ wide_header_strings + 2*(s_scanning_prefix-header_ascii_strings)
w_scan_of_prefix    equ wide_header_strings + 2*(s_scan_of_prefix-header_ascii_strings)
w_refreshing        equ wide_tail_strings + 2*(s_refreshing-tail_ascii_strings)
w_refresh_hint      equ wide_tail_strings + 2*(s_refresh_hint-tail_ascii_strings)
w_explorer          equ wide_header_strings + 2*(s_explorer-header_ascii_strings)
w_browse_title      equ wide_header_strings + 2*(s_browse_title-header_ascii_strings)
w_select_format     equ wide_tail_strings + 2*(s_select_format-tail_ascii_strings)
w_size_format       equ wide_tail_strings + 2*(s_size_format-tail_ascii_strings)

text_end:
    times TEXT_RAW_SIZE-($-$$) db 0

SECTION .bss nobits vstart=IMAGE_BASE+BSS_RVA valign=8
bss_start:
api_table:                 resq API_COUNT

; Scalar state is grouped around globals_center so the hot fields use short displacements.
globals:
globals_center equ globals+128
scan_active: resd 1
animation_active: resd 1
animation_progress: resd 1
client_height: resd 1
hovered_node: resq 1
refresh_requested: resd 1
client_width: resd 1
display_root: resq 1
hit_test_layout: resb V_BYTES
ui_scale: resd 1
render_x: resd 1
render_y: resd 1
font_height: resd 1
navigation_history: resq 1
current_view: resb V_BYTES
window_dc: resq 1
font_dc: resq 1
redraw_divider: resd 1
mouse_y: resd 1
mouse_x: resd 1
animation_back: resd 1
window_handle: resq 1
scan_tree_root: resq 1
command_line_root: resq 1
view_radius: resd 1
view_center_y: resd 1
view_center_x: resd 1
last_tick: resd 1
animation_to: resb V_BYTES
process_heap: resq 1
animation_from: resb V_BYTES
hand_cursor: resq 1
dib_bitmap: resq 1
arrow_cursor: resq 1
shell_module: resq 1
dib_pixels: resq 1
theme_dark: resd 1
computer_mode: resd 1
chart_overview: resd 1
chart_step: resd 1
chart_root: resq 1
hover_chart: resq 1
computer_pidl: resq 1
overview_scroll: resd 1
graphics: resq 1
fill_brush: resq 1
outline_pen: resq 1

wide_header_strings:       resw header_ascii_strings_end-header_ascii_strings
wide_tail_strings:         resw tail_ascii_strings_end-tail_ascii_strings
    resb (-($-$$)) & 7             ; Win32 structure pointers require natural alignment
wnd_class:                 resb 72
browse_info:               resb 64
bitmap_info:               resb 40
gp_startup:                resb 24
gp_token:                  resq 1
log_font:                  resb 92
    resb (-($-$$)) & 7
message_buffer:            resb 48
browse_selection_path:     resw 260
root_path_buffer:          resw 260
size_text_buffer:          resw 32
    resb (-($-$$)) & 7
state_critical_section:    resb 40
; Private DFS contexts. stopParent pins the donated subtree's ancestor chain.
scan_frame_stack:          resq 1
main_stop_parent:          resq 1
main_batch:                resb 24
helper_context:            resb 40*(THREAD_WORKERS-1)
executable_path:           resw 32768
bss_end:
