import pefile

EmbeddedModulePath = "bin\\LdrValkyrie.dll"
PePath = "bin\\Valkyrie.exe"

def main():
    print("")
    ValkyriePE = pefile.PE(PePath)
    FoundModuleBuffer = False
    Counter = 0

    with open(EmbeddedModulePath, "rb") as f:
        ModuleData = f.read() + b"VALK-EOF"
        ModuleSize = len(ModuleData)
        print(f"[EmbedModule.py] Module size: 0x{ModuleSize:x}")

    with open(PePath, "rb+") as f:
        for Section in ValkyriePE.sections:
            if Section.Name.rstrip(b'\x00') == b".rdata":
                RdataStart = Section.PointerToRawData
                RdataSize = Section.SizeOfRawData

        while Counter <= (RdataSize - ModuleSize):
            # Address to check for buffer
            ModuleBuffer = RdataStart + Counter
            f.seek(ModuleBuffer)
            ModulePadding = f.read(ModuleSize)

            for i in range(ModuleSize):

                # Looking for uninterrupted 0s for the entire size of the module
                if ModulePadding[i] != 0:
                    break

                # If we find a full buffer of 0s, that's where we write
                if i == ModuleSize - 1:
                    FoundModuleBuffer = True
                    break

            if not FoundModuleBuffer:
                # Keep it 16-byte aligned so as not to interfere with trailing 0s on legitimate data
                Counter += 16
            else:
                break
            
        if FoundModuleBuffer:
            print(f"[EmbedModule.py] Found .rdata padding at 0x{ModuleBuffer:x} in {PePath}")
        else:
            print("[EmbedModule.py] Failed to find .rdata padding")
            return
        
        f.seek(ModuleBuffer)
        f.write(ModuleData)

        print(f"[EmbedModule.py] Successfully wrote 0x{ModuleSize:x} bytes to .rdata padding.")
        
if __name__ == "__main__":
    main()