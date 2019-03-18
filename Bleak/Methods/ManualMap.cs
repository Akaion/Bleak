using Bleak.Methods.Interfaces;
using Bleak.Methods.Shellcode;
using Bleak.Native;
using Bleak.SafeHandle;
using Bleak.Tools;
using Bleak.Wrappers;
using System;
using System.Runtime.InteropServices;
using System.Linq;
using System.IO;

namespace Bleak.Methods
{
    internal class ManualMap : IInjectionMethod
    {
        private readonly PropertyWrapper PropertyWrapper;

        internal ManualMap(PropertyWrapper propertyWrapper)
        {
            PropertyWrapper = propertyWrapper;
        }

        public bool Call()
        {
            // Store the DLL bytes in a buffer

            var dllBaseAddress = GCHandle.Alloc(PropertyWrapper.DllBytes, GCHandleType.Pinned);

            var peHeaders = PropertyWrapper.PeParser.GetPeHeaders();

            // Map the imports the DLL into the local process

            MapImports(dllBaseAddress.AddrOfPinnedObject());

            // Allocate memory for the DLL in the target process

            var dllSize = PropertyWrapper.IsWow64Process.Value ? peHeaders.NtHeaders32.OptionalHeader.SizeOfImage : peHeaders.NtHeaders64.OptionalHeader.SizeOfImage;

            var remoteDllAddress = PropertyWrapper.MemoryManager.Value.AllocateMemory((int) dllSize, Enumerations.MemoryProtectionType.ExecuteReadWrite);

            // Perform the needed relocations in the local process

            PerformRelocations(dllBaseAddress.AddrOfPinnedObject(), remoteDllAddress);

            // Map the sections of the DLL into the target process

            MapSections(dllBaseAddress.AddrOfPinnedObject(), remoteDllAddress);

            // Calculate the entry point of the DLL in the target process

            var dllEntryPointAddress = PropertyWrapper.IsWow64Process.Value ? (uint) remoteDllAddress + peHeaders.NtHeaders32.OptionalHeader.AddressOfEntryPoint : (ulong) remoteDllAddress + peHeaders.NtHeaders64.OptionalHeader.AddressOfEntryPoint;

            // Call the entry point of the DLL in the target process

            CallDllEntryPoint(remoteDllAddress, (IntPtr) dllEntryPointAddress);

            dllBaseAddress.Free();

            return true;
        }

        private void CallDllEntryPoint(IntPtr remoteDllAddress, IntPtr dllEntryPointAddress)
        {
            // Create the shellcode used to call the entry point of the dll

            var shellcode = PropertyWrapper.IsWow64Process.Value ? CallDllMainX86.GetShellcode(remoteDllAddress, dllEntryPointAddress) : CallDllMainX64.GetShellcode(remoteDllAddress, dllEntryPointAddress);

            // Store the shellcode in a buffer in the target process

            var shellcodeBuffer = PropertyWrapper.MemoryManager.Value.AllocateMemory(shellcode.Length, Enumerations.MemoryProtectionType.ExecuteReadWrite);

            PropertyWrapper.MemoryManager.Value.WriteMemory(shellcodeBuffer, shellcode);

            // Create a remote thread in the target process to call the shellcode

            var threadHandle = (SafeThreadHandle) PropertyWrapper.SyscallManager.InvokeSyscall<Syscall.Definitions.NtCreateThreadEx>(PropertyWrapper.ProcessHandle.Value, shellcodeBuffer, IntPtr.Zero);
            
            // Wait for the remote thread to finish its task

            PInvoke.WaitForSingleObject(threadHandle, uint.MaxValue);

            // Free the memory allocated for the buffer

            PropertyWrapper.MemoryManager.Value.FreeMemory(shellcodeBuffer);

            threadHandle.Dispose();
        }

        private static Enumerations.MemoryProtectionType GetSectionProtection(Enumerations.SectionCharacteristics sectionCharacteristics)
        {
            // Determine the protection of the section
            
            var sectionProtection = (Enumerations.MemoryProtectionType) 0;

            if (sectionCharacteristics.HasFlag(Enumerations.SectionCharacteristics.MemoryNotCached))
            {
                sectionProtection |= Enumerations.MemoryProtectionType.NoCache;
            }

            if (sectionCharacteristics.HasFlag(Enumerations.SectionCharacteristics.MemoryExecute))
            {
                if (sectionCharacteristics.HasFlag(Enumerations.SectionCharacteristics.MemoryRead))
                {
                    if (sectionCharacteristics.HasFlag(Enumerations.SectionCharacteristics.MemoryWrite))
                    {
                        sectionProtection |= Enumerations.MemoryProtectionType.ExecuteReadWrite;
                    }

                    else
                    {
                        sectionProtection |= Enumerations.MemoryProtectionType.ExecuteRead;
                    }
                }

                else if (sectionCharacteristics.HasFlag(Enumerations.SectionCharacteristics.MemoryWrite))
                {
                    sectionProtection |= Enumerations.MemoryProtectionType.ExecuteWriteCopy;
                }

                else
                {
                    sectionProtection |= Enumerations.MemoryProtectionType.Execute;
                }
            }

            else if (sectionCharacteristics.HasFlag(Enumerations.SectionCharacteristics.MemoryRead))
            {
                if (sectionCharacteristics.HasFlag(Enumerations.SectionCharacteristics.MemoryWrite))
                {
                    sectionProtection |= Enumerations.MemoryProtectionType.ReadWrite;
                }

                else
                {
                    sectionProtection |= Enumerations.MemoryProtectionType.ReadOnly;
                }
            }

            else if (sectionCharacteristics.HasFlag(Enumerations.SectionCharacteristics.MemoryWrite))
            {
                sectionProtection |= Enumerations.MemoryProtectionType.WriteCopy;
            }

            else
            {
                sectionProtection |= Enumerations.MemoryProtectionType.NoAccess;
            }

            return sectionProtection;
        }

        private void MapImports(IntPtr dllBaseAddress)
        {
            // Group the imported functions by the DLL they reside in

            var groupedImports = PropertyWrapper.PeParser.GetImportedFunctions().GroupBy(importedFunction => importedFunction.DllName);

            foreach (var importedFunction in groupedImports.SelectMany(dll => dll.Select(importedFunction => importedFunction)))
            {
                var dllName = importedFunction.DllName;

                if (dllName.Contains("-ms-win-crt-"))
                {
                    dllName = "ucrtbase.dll";
                }

                // Get the address of the imported function in the target process

                var importedFunctionAddress = NativeTools.GetFunctionAddress(PropertyWrapper, dllName, importedFunction.Name);

                if (importedFunctionAddress == IntPtr.Zero)
                {
                    // Get the path of the system DLL

                    var systemFolderPath = PropertyWrapper.IsWow64Process.Value ? Environment.GetFolderPath(Environment.SpecialFolder.SystemX86) : Environment.GetFolderPath(Environment.SpecialFolder.System);

                    var systemDllPath = Path.Combine(systemFolderPath, dllName);
                    
                    // Load the system DLL into the target process

                    new Injector().NtCreateThreadEx(PropertyWrapper.Process.Id, systemDllPath);

                    // Get the address of the imported function in the target process

                    importedFunctionAddress = NativeTools.GetFunctionAddress(PropertyWrapper, dllName, importedFunction.Name);
                }

                // Calculate the address of the import

                var importAddress = (ulong) dllBaseAddress + importedFunction.Offset;

                // Map the imported function into the local process

                Marshal.WriteIntPtr((IntPtr) importAddress, importedFunctionAddress);
            }
        }

        private void MapSections(IntPtr dllBaseAddress, IntPtr remoteDllAddress)
        {
            foreach (var section in PropertyWrapper.PeParser.GetPeHeaders().SectionHeaders)
            {
                // Get the protection of the section

                var sectionProtection = GetSectionProtection(section.Characteristics);

                // Calculate the address to map the section to in the target process

                var sectionAddress = (ulong) remoteDllAddress + section.VirtualAddress;

                // Get the raw data of the section

                var rawDataAddress = (ulong) dllBaseAddress + section.PointerToRawData;

                var rawData = new byte[section.SizeOfRawData];

                Marshal.Copy((IntPtr) rawDataAddress, rawData, 0, (int) section.SizeOfRawData);

                // Map the section into the target process

                PropertyWrapper.MemoryManager.Value.WriteMemory((IntPtr) sectionAddress, rawData);

                // Adjust the protection of the section in the target process

                PropertyWrapper.MemoryManager.Value.ProtectMemory((IntPtr) sectionAddress, (int) section.SizeOfRawData, sectionProtection);
            }
        }

        private void PerformRelocations(IntPtr dllBaseAddress, IntPtr remoteDllAddress)
        {
            var peHeaders = PropertyWrapper.PeParser.GetPeHeaders();

            if ((peHeaders.FileHeader.Characteristics & (ushort) Enumerations.FileCharacteristics.RelocationsStripped) > 0)
            {
                // No relocations need to be performed

                return;
            }

            // Calculate the delta of the DLL in the target process

            var imageDelta = PropertyWrapper.IsWow64Process.Value ? (long) remoteDllAddress - peHeaders.NtHeaders32.OptionalHeader.ImageBase : (long) remoteDllAddress - (long) peHeaders.NtHeaders64.OptionalHeader.ImageBase;
            
            foreach (var relocation in PropertyWrapper.PeParser.GetBaseRelocations())
            {
                // Calculate the base address of the relocation

                var relocationBaseAddress = (ulong) dllBaseAddress + relocation.Offset;

                foreach (var typeOffset in relocation.TypeOffsets)
                {
                    // Calculate the address of relocation

                    var relocationAddress = relocationBaseAddress + typeOffset.Offset;

                    switch (typeOffset.Type)
                    {
                        case Enumerations.RelocationType.HighLow:
                        {
                            var relocationValue = Marshal.PtrToStructure<int>((IntPtr) relocationAddress) + (int) imageDelta;
                            
                            // Perform the relocation

                            Marshal.WriteInt32((IntPtr) relocationAddress, relocationValue);

                            break;
                        }
                        
                        case Enumerations.RelocationType.Dir64:
                        {
                            var relocationValue = Marshal.PtrToStructure<long>((IntPtr) relocationAddress) + imageDelta;
                            
                            // Perform the relocation

                            Marshal.WriteInt64((IntPtr) relocationAddress, relocationValue);

                            break;
                        }
                    }
                }
            }
        }
    }
}
