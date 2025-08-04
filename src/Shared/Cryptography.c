#include <Windows.h>

// Djb2 string hashing algorithm author: Dan Bernstein
// https://raw.githubusercontent.com/vxunderground/VX-API/main/VX-API/HashStringDjb2.cpp
ULONG HashDjb2A(CHAR *String){
    ULONG hash = 0xFADE;
    DWORD c = 0;

    while (c = *String++){
        hash = ((hash << 5) + hash) + c;
    }

    return hash;
}

// Djb2 string hashing algorithm author: Dan Bernstein
// https://raw.githubusercontent.com/vxunderground/VX-API/main/VX-API/HashStringDjb2.cpp
ULONG HashDjb2W(WCHAR *String){
    ULONG hash = 0xFADE;
    DWORD c = 0;

    while (c = *String++){
        hash = ((hash << 5) + hash) + c;
    }

    return hash;
}