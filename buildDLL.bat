@echo off

REM Accepted arguments = "scan", "unhook", "aggressive", "verbose"

set "ARGUMENTS=%*"
setlocal enabledelayedexpansion
set "COMPILER_ARGUMENTS="
for %%A in (%ARGUMENTS%) do (
	set "COMPILER_ARGUMENTS=!COMPILER_ARGUMENTS! /D %%A"
)
nasm.exe -fwin64 -o Syscall.obj src\Syscall.asm
cl.exe /nologo /wd 4024 /wd 4047 /LD /D DLL_BUILD %COMPILER_ARGUMENTS% src\Valkyrie.c Syscall.obj user32.lib
del Syscall.obj
del Valkyrie.obj