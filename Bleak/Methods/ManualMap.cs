using Bleak.Methods.Shellcode;
using Bleak.Native;
using Bleak.SafeHandle;
using Bleak.Syscall.Definitions;
using Bleak.Wrappers;
using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace Bleak.Methods
{
    internal class ManualMap
    {
        private readonly PropertyWrapper _propertyWrapper;

        internal ManualMap(PropertyWrapper propertyWrapper)
        {
            _propertyWrapper = propertyWrapper;
        }

        internal bool Call()
        {
            // Store the DLL bytes in a buffer

            var localDllBuffer = GCHandle.Alloc(_propertyWrapper.DllBytes, GCHandleType.Pinned);

            var localDllBaseAddress = localDllBuffer.AddrOfPinnedObject();

            var peHeaders = _propertyWrapper.PeParser.GetHeaders();

            // Map the imports the DLL into the local process

            MapImports(localDllBaseAddress);

            // Allocate memory for the DLL in the target process

            var dllSize = _propertyWrapper.TargetProcess.IsWow64 ? peHeaders.NtHeaders32.OptionalHeader.SizeOfImage : peHeaders.NtHeaders64.OptionalHeader.SizeOfImage;

            var remoteDllAddress = _propertyWrapper.MemoryManager.AllocateVirtualMemory((int) dllSize, Enumerations.MemoryProtectionType.ExecuteReadWrite);

            // Perform the needed relocations in the local process

            PerformRelocations(localDllBaseAddress, remoteDllAddress);

            // Map the sections of the DLL into the target process

            MapSections(localDllBaseAddress, remoteDllAddress);

            // Call the entry point of the DLL

            var dllEntryPointAddress = _propertyWrapper.TargetProcess.IsWow64 ? (uint) remoteDllAddress + peHeaders.NtHeaders32.OptionalHeader.AddressOfEntryPoint : (ulong) remoteDllAddress + peHeaders.NtHeaders64.OptionalHeader.AddressOfEntryPoint;

            CallEntryPoint(remoteDllAddress, (IntPtr) dllEntryPointAddress);

            localDllBuffer.Free();

            return true;
        }

        private void CallEntryPoint(IntPtr remoteDllBaseAddress, IntPtr dllEntryPointAddress)
        {
            // Write the shellcode used to call the entry point of the DLL into the target process

            var shellcode = _propertyWrapper.TargetProcess.IsWow64 ? CallDllMainX86.GetShellcode(remoteDllBaseAddress, dllEntryPointAddress) : CallDllMainX64.GetShellcode(remoteDllBaseAddress, dllEntryPointAddress);

            var shellcodeBuffer = _propertyWrapper.MemoryManager.AllocateVirtualMemory(shellcode.Length, Enumerations.MemoryProtectionType.ExecuteReadWrite);

            _propertyWrapper.MemoryManager.WriteVirtualMemory(shellcodeBuffer, shellcode);

            // Create a thread to call the shellcode in the target process

            var threadHandle = (SafeThreadHandle) _propertyWrapper.SyscallManager.InvokeSyscall<NtCreateThreadEx>(_propertyWrapper.TargetProcess.ProcessHandle, shellcodeBuffer, IntPtr.Zero);

            PInvoke.WaitForSingleObject(threadHandle, uint.MaxValue);

            _propertyWrapper.MemoryManager.FreeVirtualMemory(shellcodeBuffer);

            threadHandle.Dispose();
        }

        private Enumerations.MemoryProtectionType GetSectionProtection(Enumerations.SectionCharacteristics sectionCharacteristics)
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

        private void MapImports(IntPtr localDllBaseAddress)
        {
            // Group the imported functions by the DLL they reside in

            var groupedImports = _propertyWrapper.PeParser.GetImportedFunctions().GroupBy(importedFunction => importedFunction.DllName);

            foreach (var importedDll in groupedImports)
            {
                var dllName = importedDll.Key;

                if (dllName.Contains("-ms-win-crt-"))
                {
                    dllName = "ucrtbase.dll";
                }

                if (!_propertyWrapper.TargetProcess.ProcessModules.Any(module => module.Name.Equals(dllName, StringComparison.OrdinalIgnoreCase)))
                {
                    var systemFolderPath = _propertyWrapper.TargetProcess.IsWow64 ? Environment.GetFolderPath(Environment.SpecialFolder.SystemX86) : Environment.GetFolderPath(Environment.SpecialFolder.System);

                    // Load the DLL into the target process

                    new Injector().CreateRemoteThread(_propertyWrapper.TargetProcess.Process.Id, Path.Combine(systemFolderPath, dllName));
                }
            }

            _propertyWrapper.TargetProcess.Refresh();

            foreach (var importedFunction in groupedImports.SelectMany(dll => dll.Select(importedFunction => importedFunction)))
            {
                var dllName = importedFunction.DllName;

                if (dllName.Contains("-ms-win-crt-"))
                {
                    dllName = "ucrtbase.dll";
                }

                // Get the address of the imported function

                var importedFunctionAddress = _propertyWrapper.TargetProcess.GetFunctionAddress(dllName, importedFunction.Name);

                // Map the imported function into the local process

                var importAddress = (ulong) localDllBaseAddress + importedFunction.Offset;

                Marshal.WriteIntPtr((IntPtr) importAddress, importedFunctionAddress);
            }
        }

        private void MapSections(IntPtr localDllBaseAddress, IntPtr remoteDllBaseAddress)
        {
            foreach (var section in _propertyWrapper.PeParser.GetHeaders().SectionHeaders)
            {
                // Get the raw data of the section

                var rawDataAddress = (ulong) localDllBaseAddress + section.PointerToRawData;

                var rawData = new byte[section.SizeOfRawData];

                Marshal.Copy((IntPtr) rawDataAddress, rawData, 0, (int) section.SizeOfRawData);

                // Map the section into the target process

                var sectionAddress = (ulong) remoteDllBaseAddress + section.VirtualAddress;

                _propertyWrapper.MemoryManager.WriteVirtualMemory((IntPtr) sectionAddress, rawData);

                // Adjust the protection of the section in the target process

                var sectionProtection = GetSectionProtection(section.Characteristics);

                _propertyWrapper.MemoryManager.ProtectVirtualMemory((IntPtr) sectionAddress, (int) section.SizeOfRawData, sectionProtection);
            }
        }

        private void PerformRelocations(IntPtr localDllBaseAddress, IntPtr remoteDllBaseAddress)
        {
            var peHeaders = _propertyWrapper.PeParser.GetHeaders();

            if ((peHeaders.FileHeader.Characteristics & (ushort) Enumerations.FileCharacteristics.RelocationsStripped) > 0)
            {
                // No relocations need to be performed

                return;
            }

            // Calculate the delta of the DLL in the target process

            var delta = _propertyWrapper.TargetProcess.IsWow64 ? (long) remoteDllBaseAddress - peHeaders.NtHeaders32.OptionalHeader.ImageBase : (long) remoteDllBaseAddress - (long) peHeaders.NtHeaders64.OptionalHeader.ImageBase;

            if (delta == 0)
            {
                // The DLL is loaded at its base address and no relocations need to be performed

                return;
            }

            foreach (var relocation in _propertyWrapper.PeParser.GetBaseRelocations())
            {
                // Calculate the base address of the relocation

                var relocationBaseAddress = (ulong) localDllBaseAddress + relocation.Offset;

                foreach (var typeOffset in relocation.TypeOffsets)
                {
                    // Calculate the address of the relocation

                    var relocationAddress = relocationBaseAddress + typeOffset.Offset;

                    switch (typeOffset.Type)
                    {
                        case Enumerations.RelocationType.HighLow:
                        {
                            var relocationValue = Marshal.PtrToStructure<int>((IntPtr) relocationAddress) + (int) delta;
                            
                            // Perform the relocation

                            Marshal.WriteInt32((IntPtr) relocationAddress, relocationValue);
                            
                            break;
                        } 
                        
                        case Enumerations.RelocationType.Dir64:
                        {
                            var relocationValue = Marshal.PtrToStructure<long>((IntPtr) relocationAddress) + delta;
                            
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
