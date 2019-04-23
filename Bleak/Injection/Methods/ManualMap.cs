using Bleak.Injection.Interfaces;
using Bleak.Injection.Methods.Shellcode;
using Bleak.Injection.Objects;
using Bleak.Memory;
using Bleak.Native;
using Bleak.Native.SafeHandle;
using Bleak.PortableExecutable;
using Bleak.PortableExecutable.Objects;
using Bleak.Syscall.Definitions;
using Bleak.Tools;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace Bleak.Injection.Methods
{
    internal class ManualMap : IInjectionMethod
    {
        private void BuildImportTable(InjectionProperties injectionProperties, IntPtr localDllAddress)
        {
            var importedFunctions = injectionProperties.PeParser.GetImportedFunctions();

            if (importedFunctions.Count == 0)
            {
                // The DLL has no imported functions

                return;
            }

            // Group the imported functions by the DLL they reside in

            var groupedFunctions = importedFunctions.GroupBy(importedFunction => importedFunction.DllName).ToList();

            // Get the API set mappings

            List<ApiSetMapping> apiSetMappings;

            using (var peParser = new PeParser(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "apisetschema.dll")))
            {
                apiSetMappings = peParser.GetApiSetMappings();
            }

            var systemFolderPath = injectionProperties.RemoteProcess.IsWow64
                                 ? Environment.GetFolderPath(Environment.SpecialFolder.SystemX86)
                                 : Environment.GetFolderPath(Environment.SpecialFolder.System);

            foreach (var dll in groupedFunctions)
            {
                var dllName = dll.Key;

                if (dllName.StartsWith("api-ms"))
                {
                    dllName = apiSetMappings.Find(apiSetMapping => apiSetMapping.VirtualDll.Equals(dllName, StringComparison.OrdinalIgnoreCase)).MappedToDll;
                }

                // Ensure the DLL is loaded in the target process

                if (!injectionProperties.RemoteProcess.Modules.Any(module => module.Name.Equals(dllName, StringComparison.OrdinalIgnoreCase)))
                {
                    // Load the DLL into the target process

                    new Injector().CreateRemoteThread(injectionProperties.RemoteProcess.TargetProcess.Id, Path.Combine(systemFolderPath, dllName));
                }
            }

            injectionProperties.RemoteProcess.Refresh();

            foreach (var importedFunction in groupedFunctions.SelectMany(dll => dll.Select(importedFunction => importedFunction)))
            {
                var dllName = importedFunction.DllName;

                if (dllName.StartsWith("api-ms"))
                {
                    dllName = apiSetMappings.Find(apiSetMapping => apiSetMapping.VirtualDll.Equals(dllName, StringComparison.OrdinalIgnoreCase)).MappedToDll;
                }

                // Get the address of the imported function

                var importedFunctionAddress = injectionProperties.RemoteProcess.GetFunctionAddress(dllName, importedFunction.Name);

                // Write the imported function into the local process

                Marshal.WriteInt64(localDllAddress.AddOffset(importedFunction.Offset), (long) importedFunctionAddress);
            }
        }

        public bool Call(InjectionProperties injectionProperties)
        {
            var localDllAddress = injectionProperties.DllPath is null
                                ? LocalMemoryTools.StoreBytesInBuffer(injectionProperties.DllBytes)
                                : LocalMemoryTools.StoreBytesInBuffer(File.ReadAllBytes(injectionProperties.DllPath));

            // Build the import table of the DLL

            BuildImportTable(injectionProperties, localDllAddress);

            var peHeaders = injectionProperties.PeParser.GetHeaders();

            // Allocate memory for the DLL in the target process

            var allocationBaseAddress = injectionProperties.RemoteProcess.IsWow64
                                      ? peHeaders.NtHeaders32.OptionalHeader.ImageBase
                                      : peHeaders.NtHeaders64.OptionalHeader.ImageBase;

            var dllSize = injectionProperties.RemoteProcess.IsWow64
                        ? peHeaders.NtHeaders32.OptionalHeader.SizeOfImage
                        : peHeaders.NtHeaders64.OptionalHeader.SizeOfImage;

            IntPtr remoteDllAddress;

            try
            {
                remoteDllAddress = injectionProperties.MemoryManager.AllocateVirtualMemory((IntPtr) allocationBaseAddress, (int) dllSize, Enumerations.MemoryProtectionType.ExecuteReadWrite);
            }

            catch (Win32Exception)
            {
                remoteDllAddress = injectionProperties.MemoryManager.AllocateVirtualMemory(IntPtr.Zero, (int) dllSize, Enumerations.MemoryProtectionType.ExecuteReadWrite);
            }

            // Perform any needed relocations

            PerformRelocations(injectionProperties, localDllAddress, remoteDllAddress);

            // Map the sections of the DLL

            MapSections(injectionProperties, localDllAddress, remoteDllAddress);

            // Map randomised PE headers

            MapHeaders(injectionProperties, remoteDllAddress);

            // Call any TLS callbacks

            CallTlsCallbacks(injectionProperties, remoteDllAddress);

            // Call the entry point of the DLL

            var dllEntryPointAddress = injectionProperties.RemoteProcess.IsWow64
                                     ? remoteDllAddress.AddOffset(peHeaders.NtHeaders32.OptionalHeader.AddressOfEntryPoint)
                                     : remoteDllAddress.AddOffset(peHeaders.NtHeaders64.OptionalHeader.AddressOfEntryPoint);

            if (dllEntryPointAddress != remoteDllAddress)
            {
                CallEntryPoint(injectionProperties, remoteDllAddress, dllEntryPointAddress);
            }

            LocalMemoryTools.FreeMemoryForBuffer(localDllAddress);

            return true;
        }

        private void CallEntryPoint(InjectionProperties injectionProperties, IntPtr remoteDllAddress, IntPtr entryPointAddress)
        {
            // Write the shellcode used to call the entry point of the DLL or TLS callback in the target process

            var shellcode = injectionProperties.RemoteProcess.IsWow64
                          ? CallDllMainX86.GetShellcode(remoteDllAddress, entryPointAddress)
                          : CallDllMainX64.GetShellcode(remoteDllAddress, entryPointAddress);

            var shellcodeBuffer = injectionProperties.MemoryManager.AllocateVirtualMemory(IntPtr.Zero, shellcode.Length, Enumerations.MemoryProtectionType.ExecuteReadWrite);

            injectionProperties.MemoryManager.WriteVirtualMemory(shellcodeBuffer, shellcode);

            // Create a thread to call the shellcode in the target process

            var remoteThreadHandle = (SafeThreadHandle) injectionProperties.SyscallManager.InvokeSyscall<NtCreateThreadEx>(injectionProperties.RemoteProcess.Handle, shellcodeBuffer, IntPtr.Zero);

            PInvoke.WaitForSingleObject(remoteThreadHandle, uint.MaxValue);

            injectionProperties.MemoryManager.FreeVirtualMemory(shellcodeBuffer);

            remoteThreadHandle.Dispose();
        }

        private void CallTlsCallbacks(InjectionProperties injectionProperties, IntPtr remoteDllAddress)
        {
            foreach (var tlsCallback in injectionProperties.PeParser.GetTlsCallbacks())
            {
                CallEntryPoint(injectionProperties, remoteDllAddress, remoteDllAddress.AddOffset(tlsCallback.Offset));
            }
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

            else
            {
                if (sectionCharacteristics.HasFlag(Enumerations.SectionCharacteristics.MemoryRead))
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
            }

            return sectionProtection;
        }

        private void MapHeaders(InjectionProperties injectionProperties, IntPtr remoteDllAddress)
        {
            // Determine the size of the PE headers of the DLL

            var headerSize = injectionProperties.RemoteProcess.IsWow64
                           ? injectionProperties.PeParser.GetHeaders().NtHeaders32.OptionalHeader.SizeOfHeaders
                           : injectionProperties.PeParser.GetHeaders().NtHeaders64.OptionalHeader.SizeOfHeaders;

            var headerBytes = new byte[headerSize];

            // Fill the header bytes with random bytes

            new Random().NextBytes(headerBytes);

            // Write the PE headers into the target process

            injectionProperties.MemoryManager.WriteVirtualMemory(remoteDllAddress, headerBytes);

            // Adjust the protection of the PE header region

            injectionProperties.MemoryManager.ProtectVirtualMemory(remoteDllAddress, (int) headerSize, Enumerations.MemoryProtectionType.ReadOnly);
        }

        private void MapSections(InjectionProperties injectionProperties, IntPtr localDllAddress, IntPtr remoteDllAddress)
        {
            foreach (var section in injectionProperties.PeParser.GetHeaders().SectionHeaders)
            {
                // Get the data of the section

                var sectionDataAddress = localDllAddress.AddOffset(section.PointerToRawData);

                var sectionData = new byte[section.SizeOfRawData];

                Marshal.Copy(sectionDataAddress, sectionData, 0, (int) section.SizeOfRawData);

                // Write the section into the target process

                var sectionAddress = remoteDllAddress.AddOffset(section.VirtualAddress);

                injectionProperties.MemoryManager.WriteVirtualMemory(sectionAddress, sectionData);

                // Adjust the protection of the section

                var sectionProtection = GetSectionProtection(section.Characteristics);

                injectionProperties.MemoryManager.ProtectVirtualMemory(sectionAddress, (int) section.SizeOfRawData, sectionProtection);
            }
        }

        private void PerformRelocations(InjectionProperties injectionProperties, IntPtr localDllAddress, IntPtr remoteDllAddress)
        {
            var baseRelocations = injectionProperties.PeParser.GetBaseRelocations();

            if (baseRelocations.Count == 0)
            {
                // No relocations need to be applied

                return;
            }

            var peHeaders = injectionProperties.PeParser.GetHeaders();

            var baseAddress = injectionProperties.RemoteProcess.IsWow64 
                            ? peHeaders.NtHeaders32.OptionalHeader.ImageBase
                            : peHeaders.NtHeaders64.OptionalHeader.ImageBase;

            // Calculate the base address delta

            var delta = (long) remoteDllAddress - (long) baseAddress;

            if (delta == 0)
            {
                // The DLL is loaded at its default base address and no relocations need to be applied

                return;
            }

            foreach (var baseRelocation in baseRelocations)
            {
                // Calculate the base address of the relocation block

                var relocationBlockAddress = localDllAddress.AddOffset(baseRelocation.Offset);

                foreach (var relocation in baseRelocation.Relocations)
                {
                    // Calculate the address of the relocation

                    var relocationAddress = relocationBlockAddress.AddOffset(relocation.Offset);

                    switch (relocation.Type)
                    {
                        case Enumerations.RelocationType.HighLow:
                        {
                            // Perform the relocation

                            var relocationValue = Marshal.ReadInt32(relocationAddress) + (int) delta;
                            
                            Marshal.WriteInt32(relocationAddress, relocationValue);
                            
                            break;
                        }
                        
                        case Enumerations.RelocationType.Dir64:
                        {
                            // Perform the relocation

                            var relocationValue = Marshal.ReadInt64(relocationAddress) + delta;
                            
                            Marshal.WriteInt64(relocationAddress, relocationValue);
                            
                            break;
                        }
                    }
                }
            }
        }

        
    }
}
