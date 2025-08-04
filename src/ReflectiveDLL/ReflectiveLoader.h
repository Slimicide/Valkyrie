#pragma once

#include <Windows.h>

// Reflective modules need their functions dynamically resolved during loading

typedef BOOL (WINAPI * pDllMain) (HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
pDllMain _DllMain = NULL;

// NTDLL Functions
typedef NTSTATUS (NTAPI * pNtFlushInstructionCache) (HANDLE ProcessHandle,
                                                     PVOID  BaseAddress,
                                                     SIZE_T Length);
                                                    
pNtFlushInstructionCache _NtFlushInstructionCache = NULL;

// Kernel32 Functions
typedef HANDLE (WINAPI * pCreateFileA) (LPCSTR                lpFileName,
                                        DWORD                 dwDesiredAccess,
                                        DWORD                 dwShareMode,
                                        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                                        DWORD                 dwCreationDisposition,
                                        DWORD                 dwFlagsAndAttributes,
                                        HANDLE                hTemplateFile);

typedef BOOL (WINAPI * pWriteFile) (HANDLE       hFile,
                                    LPCVOID      lpBuffer,
                                    DWORD        nNumberOfBytesToWrite,
                                    LPDWORD      lpNumberOfBytesWritten,
                                    LPOVERLAPPED lpOverlapped);

typedef HMODULE (WINAPI * pLoadLibraryA)   (LPCSTR lpLibFileName);
typedef DWORD   (WINAPI * pGetLastError)   ();
typedef VOID    (WINAPI * pDebugBreak)     ();
typedef VOID    (WINAPI * pSleep)          (DWORD dwMilliseconds);
typedef BOOL    (WINAPI * pCloseHandle)    (HANDLE hObject);

typedef BOOL    (WINAPI * pVirtualProtect) (LPVOID lpAddress,
                                            SIZE_T dwSize,
                                            DWORD  flNewProtect,
                                            PDWORD lpflOldProtect);

pCreateFileA    _CreateFileA    = NULL;
pWriteFile      _WriteFile      = NULL;
pLoadLibraryA   _LoadLibraryA   = NULL;
pGetLastError   _GetLastError   = NULL;
pDebugBreak     _DebugBreak     = NULL;
pSleep          _Sleep          = NULL;
pVirtualProtect _VirtualProtect = NULL;
pCloseHandle    _CloseHandle    = NULL;

// MSVCRT Functions
typedef void * (WINAPI * pMalloc)  (size_t size);
typedef int    (WINAPI * pPrintf)  (const char *format, ...);
typedef int    (WINAPI * pSprintf) (char *buffer, const char *format, ...);
typedef size_t (WINAPI * pStrlen)  (const char *str);
typedef void * (WINAPI * pMemcpy)  (void *dest, const void *src, size_t count);
typedef char * (WINAPI * pStrchr)  (const char *str, int c);

pMalloc  _Malloc  = NULL;
pPrintf  _Printf  = NULL;
pSprintf _Sprintf = NULL;
pStrlen  _Strlen  = NULL;
pMemcpy  _Memcpy  = NULL;
pStrchr  _Strchr  = NULL;

INT ModuleMain();