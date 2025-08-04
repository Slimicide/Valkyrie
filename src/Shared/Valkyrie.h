#pragma once

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <winternl.h>

#define ANSI_WHITE  "\033[0m"
#define ANSI_RED    "\033[31m"
#define ANSI_GREEN  "\033[32m"
#define ANSI_YELLOW "\033[33m"
#define ANSI_BLUE   "\033[34m"

#define MESSAGE_INFO  "\033[33mINFO\033[0m"
#define MESSAGE_PIPE  "\033[33mPIPE\033[0m"
#define MESSAGE_ERROR "\033[31mERROR\033[0m"
#define MESSAGE_DEBUG "\033[34mDEBUG\033[0m"

#define CLASSIFIER_NULL        "\033[31mNULL\033[0m"
#define CLASSIFIER_MEM_PRIVATE "\033[31mPRIVATE MEMORY\033[0m"
#define CLASSIFIER_MEM_INVALID "\033[31mINVALID MEMORY\033[0m"

// --------------------------

#define VALKYRIE_ARGUMENT_PID  "\033[33mPID\033[0m"
#define VALKYRIE_ARGUMENT_PATH "\033[33mPATH\033[0m"

#define VALKYRIE_PIPE_NAME "\\\\.\\pipe\\Valkyrie"

#define VALKYRIE_PIPE_IDENTIFY_LOADER "VALK-ID-LDR"
#define VALKYRIE_PIPE_IDENTIFY_MODULE "VALK-ID-MDL"

#define VALKYRIE_PIPE_ARGUMENT_SYN    "VALK-ARG-SYN"
#define VALKYRIE_PIPE_ARGUMENT_ACK    "VALK-ARG-ACK"
#define VALKYRIE_PIPE_ARGUMENT_NEXT   "VALK-ARG-NEXT"
#define VALKYRIE_PIPE_ARGUMENT_FINISH "VALK-ARG-TERM"

#define VALKYRIE_PIPE_ARGUMENT_UNHOOK "VALK-ARG-UNHOOK"
#define VALKYRIE_PIPE_ARGUMENT_ALLJMP "VALK-ARG-ALLJMP"

#define VALKYRIE_PIPE_DATA_SYN    "VALK-DATA-SYN"
#define VALKYRIE_PIPE_DATA_ACK    "VALK-DATA-ACK"
#define VAYLKRIE_PIPE_DATA_FINISH "VALK-DATA-TERM"

#define VALKYRIE_PIPE_TERMINATE "VALK-TERM"
#define VALKYRIE_PIPE_TIMEOUT 100

#define EMBEDDED_SIZE 0x30000 // Needs to exceed LdrValkyrie.dll size

// --------------------------

#define VALKYRIE_MAX_STRING_LENGTH 256

// --------------------------

#define SHORT_JUMP  0xEB
#define NEAR_JUMP   0xE9
#define MODRM_JUMP  0xFF
#define LOOPNE_JUMP 0xE0

#define REX_BYTE    0x48

// --------------------------

typedef enum _HOOK_TYPE{
    HookTypeNull,
    HookTypeIAT,
    HookTypeInline
} HOOK_TYPE;

typedef enum _SERIALIZED_DATA_TYPE{
    EnumJumpCount,
    EnumHookType,
    EnumFunctionName,
    EnumAddress,
    EnumModuleName
} SERIALIZED_DATA_TYPE;

typedef struct _LOADED_MODULE_LIST{
    LDR_DATA_TABLE_ENTRY **LoadedModules;
    DWORD ModuleCount;
} LOADED_MODULE_LIST, *PLOADED_MODULE_LIST;

// Contains information about an individual jump including the module the jump is in
typedef struct _JUMP{
    DWORD HookType;      // Only the first "jump" will have a hook type
    VOID *Address;
    CHAR *FunctionName;
    CHAR *ModuleName;
} JUMP, *PJUMP;

// Contains information tracking where a jump located at a function goes, following subsequent jumps
typedef struct _JUMP_CHAIN{
    JUMP **Jumps;
    DWORD JumpCount;
} JUMP_CHAIN, *PJUMP_CHAIN;

typedef struct _VALKYRIE_ARGUMENTS{
    DWORD InjectPID;
    CHAR *InjectProcess;
    BOOL  Unhook;
    BOOL  ListAllJumps;
} VALKYRIE_ARGUMENTS, *PVALKYRIE_ARGUMENTS;

// --------------------------

// Hashed with Djb2 - See Cryptography.c
// Initial value: 0xFADE

// DLLs
#define HASH_DLL_NTDLL    0x39B3FE6  //ntdll.dll
#define HASH_DLL_KERNEL32 0xB8EB08AE //KERNEL32.DLL
#define HASH_DLL_VALKYRIE 0xC0C55AB1 //LdrValkyrie.dll
#define HASH_DLL_MSVCRT   0xF924F887 //msvcrt.dll

// NTDLL Functions
#define HASH_FUNC_NTPROTECTVIRTUALMEMORY  0xB49F9961 //NtProtectVirtualMemory
#define HASH_FUNC_NTALLOCATEVIRTUALMEMORY 0xA2D0CD05 //NtAllocateVirtualMemory
#define HASH_FUNC_NTFLUSHINSTRUCTIONCACHE 0xBB554498 //NtFlushInstructionCache
#define HASH_FUNC_NTQUERYVIRTUALMEMORY    0x33B34AB6 //NtQueryVirtualMemory

// Kernel32 Functions
#define HASH_FUNC_LOADLIBRARYA   0xAACF6454 //LoadLibraryA
#define HASH_FUNC_CREATEFILEA    0x1C68B233 //CreateFileA
#define HASH_FUNC_WRITEFILE      0x470476A9 //WriteFile
#define HASH_FUNC_GETLASTERROR   0x6B925E3C //GetLastError
#define HASH_FUNC_VIRTUALPROTECT 0xD1099F26 //VirtualProtect
#define HASH_FUNC_CLOSEHANDLE    0x6942B640 //CloseHandle

// MSVCRT Functions
#define HASH_FUNC_MALLOC  0x25AFD1D6 //malloc
#define HASH_FUNC_PRINTF  0x2DE15051 //printf
#define HASH_FUNC_SPRINTF 0xCCEFC6C4 //sprintf
#define HASH_FUNC_STRLEN  0x3509E036 //strlen
#define HASH_FUNC_MEMCPY  0x25F89A29 //memcpy
#define HASH_FUNC_STRCHR  0x3509BA54 //strchr

// --------------------------

// Syscall.asm - NOTE: LPVOID SyscallAddress is not a part of the actual function, it exists to enable the indirect syscall
// Definitions: 
// http://undocumented.ntinternals.net/index.html
// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvirtualmemory
extern NTSTATUS Sys_NtProtectVirtualMemory  (HANDLE  ProcessHandle,
                                             PVOID   *BaseAddress,
                                             PSIZE_T NumberOfBytesToProtect,
                                             ULONG   NewAccessProtection,
                                             PULONG  OldAccessProtection,
                                             LPVOID  SyscallAddress);

extern NTSTATUS Sys_NtAllocateVirtualMemory (HANDLE    ProcessHandle,
                                             PVOID     *BaseAddress,
                                             ULONG_PTR ZeroBits,
                                             PSIZE_T   RegionSize,
                                             ULONG     AllocationType,
                                             ULONG     Protect,
                                             LPVOID    SyscallAddress);

extern NTSTATUS Sys_NtQueryVirtualMemory    (HANDLE  ProcessHandle,
                                             PVOID   BaseAddress,
                                             INT     MemoryInformationClass, // It's a single-member enum, just specify 0
                                             PVOID   Buffer,
                                             SIZE_T  Length,
                                             PSIZE_T ResultLength,
                                             LPVOID  SyscallAddress);

// Cryptography.c
ULONG HashDjb2A (CHAR  *FunctionName);
ULONG HashDjb2W (WCHAR *FunctionName);

// Jumps.c
CHAR *       SerializeJumps       (JUMP_CHAIN *JumpChain);
JUMP_CHAIN * DeserializeJumps     (CHAR *SerializedJumpChain);
JUMP_CHAIN * BuildInlineJumpChain (VOID *JumpAddress);
JUMP_CHAIN * BuildIATJumpChain    (VOID *HookedAddress, VOID *ActualAddress, CHAR *FunctionName);
VOID         ExpandJumpChainArray (JUMP_CHAIN ***JumpChainArray, DWORD *MaxJumpChain);
VOID         RevealJumpChain      (JUMP_CHAIN *JumpChain);
BOOL         CheckForJump         (BYTE *CheckAddress);
VOID *       DetermineJump        (BYTE *JumpSource);
BOOL         IsMaliciousJump      (JUMP_CHAIN *JumpChain);

// IPC.c
JUMP_CHAIN **ValkyriePipeControl (HANDLE ModuleThread, VALKYRIE_ARGUMENTS Arguments, DWORD *JumpChainsCollected);
BOOL         WriteToPipe         (HANDLE hPipe, CHAR *Message);
VOID         WaitForPipeRead     (HANDLE hPipe, CHAR *PreviousMessage);
BOOL         WaitForMessage      (HANDLE hPipe, CHAR *Message);

// ModuleResolution.c
LPVOID FindEmbeddedModule           (HMODULE ValkyrieBase);
SIZE_T GetEmbeddedModuleSize        (LPVOID EmbeddedModule, CHAR *EofPattern);
DWORD  OffsetResolver               (HMODULE ModuleBase, DWORD dwRVA);
DWORD  LocateFunctionOffsetFromFile (LPVOID ModuleBase, CHAR *TargetFunction);

// Utilities.c
FARPROC                CustomGetProcAddress      (HMODULE BaseAddress, ULONG HashedFunctionName);
CHAR *                 GetFunctionName           (HMODULE BaseAddress, VOID *FunctionAddress);
HMODULE                CustomGetModuleHandleHash (ULONG ModuleHash);
HMODULE                CustomGetModuleHandle     (CHAR *ModuleName);
BOOL                   ProbeForValidMemory       (VOID *Pointer);
LDR_DATA_TABLE_ENTRY * DetermineModule           (VOID *CheckAddress);
BOOL                   IsForwarder               (CHAR *FunctionAddress);
FARPROC                ProcessForwarder          (CHAR *FunctionAddress);
LDR_DATA_TABLE_ENTRY * GetLoadedModule           (CHAR *ModuleName);
LOADED_MODULE_LIST *   GetLoadedModules          ();
BOOL                   ANSIToWide                (CHAR *ANSIString, WCHAR *WideBuffer, DWORD WideBufferSize);
WCHAR                  ToLowerWide               (WCHAR Character);
BOOL                   WideToANSI                (WCHAR *WideString, CHAR *ANSIBuffer, DWORD ANSIBufferSize);

// Scan.c
ULONGLONG    CheckForIATHook       (HMODULE BaseAddress, ULONGLONG CmpFunctionIdentifier, ULONGLONG *CmpFunctionAddress);
JUMP_CHAIN **ScanImportedFunctions (HMODULE BaseAddress, BOOL Unhook, BOOL ListAllJumps, DWORD *JumpChainsCollected);
VOID         ScanModuleFunctions   (HMODULE BaseAddress);

// Hooks.c
BOOL UnhookInline               (VOID *UnhookAddress, CHAR *ModuleName);
BOOL UnhookIAT                  (ULONGLONG *IATFunctionAddress, ULONGLONG TrueFunctionAddress);
BOOL CheckFunctionHookException (CHAR *FunctionName);

// Debug.c
VOID SimulateInlineHook  (BYTE *FunctionAddress);
VOID SimulateIATHook     (HMODULE BaseAddress);
VOID ListModuleArguments (VALKYRIE_ARGUMENTS *Arguments);