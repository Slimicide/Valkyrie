#include "..\Shared\Valkyrie.h"

// Simulates an invalid memory jump at FunctionAddress to test inline hook detection
VOID SimulateInlineHook(BYTE *FunctionAddress){
    printf("[%s] Simulating an inline hook at %p\n", MESSAGE_DEBUG, FunctionAddress);
    DWORD OldProtect;

    VirtualProtect(FunctionAddress, 4096, PAGE_EXECUTE_READWRITE, &OldProtect);
    *FunctionAddress = 0xe9; // Set a jump to invalid memory

    return;
}

// Simulates an IAT hook on the process whose base is BaseAddress to test IAT hook detection
VOID SimulateIATHook(HMODULE BaseAddress){
    printf("[%s] Simulating an IAT hook on the first imported function\n", MESSAGE_DEBUG);
    DWORD OldProtect;

    IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)BaseAddress;
    IMAGE_NT_HEADERS *NtHeader  = (IMAGE_NT_HEADERS *)(DosHeader->e_lfanew + (BYTE *)BaseAddress);

    IMAGE_IMPORT_DESCRIPTOR *ImportDirectory  = (IMAGE_IMPORT_DESCRIPTOR *)(NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (BYTE *)BaseAddress);
    IMAGE_THUNK_DATA *       IAT              = (IMAGE_THUNK_DATA *)(ImportDirectory->FirstThunk + (BYTE *)BaseAddress);

    VirtualProtect(&IAT->u1.Function, 4096, PAGE_READWRITE, &OldProtect);
    IAT->u1.Function = 0xDEADBEEFDEADBEEF;
}

// Lists out received Valkyrie arguments to validate successful IPC transmission
VOID ListModuleArguments(VALKYRIE_ARGUMENTS *Arguments){
    if(Arguments->InjectProcess == NULL){
        CHAR NullString[7] = { '(', 'n', 'u', 'l', 'l', ')', '\0'};
        Arguments->InjectProcess = NullString;
    }
    printf("[%s] Received module arguments:\n\tInjectPID: %d\n\tInjectProcess: %s\n\tListAllJumps: %d\n\tUnhook: %d\n",
        MESSAGE_DEBUG,
        Arguments->InjectPID,
        Arguments->InjectProcess,
        Arguments->ListAllJumps,
        Arguments->Unhook
    );
    return;
}