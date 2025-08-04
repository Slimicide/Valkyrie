section .text
    global Sys_NtProtectVirtualMemory
    global Sys_NtAllocateVirtualMemory
    global Sys_NtQueryVirtualMemory

    Sys_NtProtectVirtualMemory:
        mov r10, rcx            ; Preserve RCX for transition to kernel-mode
        mov rax, 0x50           ; Move syscall number for NtProtectVirtualMemory to RAX
        jmp qword [RSP+0x30]    ; Passed as parameter #6 (syscall in NTDLL)

    Sys_NtAllocateVirtualMemory:
        mov r10, rcx            ; Preserve RCX for transition to kernel-mode
        mov rax, 0x18           ; Move syscall number for NtAllocateVirtualMemory to RAX
        jmp qword [RSP+0x38]    ; Passed as parameter #7 (syscall in NTDLL)
    
    Sys_NtQueryVirtualMemory:
        mov r10, rcx            ; Preserve RCX for transition to kernel-mode
        mov rax, 0x23           ; Move syscall number for NtQueryVirtualMemory to RAX
        jmp qword [RSP+0x38]    ; Passed as parameter #7 (syscall in NTDLL)