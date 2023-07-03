section .text
    global Sys_NtProtectVirtualMemory
    Sys_NtProtectVirtualMemory:
        mov r10, rcx            ; Preserve RCX for transition to kernel-mode
        mov rax, 0x50           ; Move syscall number for NtProtectVirtualMemory to RAX
        jmp qword [RSP+0x30]    ; Passed as parameter #6 (syscall in NTDLL)