@echo off
nasm.exe -fwin64 -o Syscall.obj src\Syscall.asm
cl.exe /nologo src\Valkyrie.c Syscall.obj user32.lib
del Syscall.obj
del Valkyrie.obj