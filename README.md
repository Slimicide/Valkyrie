# Valkyrie
![](images/Banner.png)

A Windows function hook detection / unhooking tool written in C.

# IAT Hook Detection & Unhooking
![](images/IAT_Unhooking.png)

# Inline Hook Detection & Unhooking
![](images/Inline_Unhooking.png)

# Usage
```
-h   Display help banner.
-a   Parse every loaded module's functions for inline hooks.
-s   Scan for both IAT hooks and inline hooks.
-u   Unhook detected hooks.
-v   Verbose output.
```

# Current Shortcomings
Valkyrie relies on VirtualProtect to perform inline unhooking by temporarily modifying module memory page permissions.

If VirtualProtect is hooked, well, you see the problem.

# References
* [Sektor7](https://institute.sektor7.net/)
* [AMD64 Architecture Programmer’s Manual](https://www.amd.com/system/files/TechDocs/40332.pdf)
* [Vergilius Project](https://www.vergiliusproject.com/kernels/x64/Windows%2011/22H2%20(2022%20Update))
