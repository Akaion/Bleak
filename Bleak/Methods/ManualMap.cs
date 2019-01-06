using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Bleak.Etc;
using Jupiter;
using PeNet;
using static Bleak.Etc.Native;

namespace Bleak.Methods
{
    internal class ManualMap
    {
        private readonly MemoryModule _memoryModule;

        private Process _process;
        
        internal ManualMap()
        {
            _memoryModule = new MemoryModule();
        }
        
        internal bool Inject(Process process, string dllPath)
        {
            _process = process;
            
            // Get the id of the process

            var processId = _process.Id;
            
            // Get the bytes of the dll
            
            var dllBytes = File.ReadAllBytes(dllPath);
            
            // Pin the dll bytes in the memory of the host process

            var baseAddress = GCHandle.Alloc(dllBytes, GCHandleType.Pinned);
         
            // Get the pe headers of the dll
            
            var peHeaders = new PeFile(dllPath);
            
            // Allocate memory for the dll in the remote process

            var dllSize = peHeaders.ImageNtHeaders.OptionalHeader.SizeOfImage;

            var remoteDllAddress = _memoryModule.AllocateMemory(processId, (int) dllSize);
            
            // Map the imports of the dll into the host process

            if (!MapImports(peHeaders, baseAddress.AddrOfPinnedObject()))
            {
                return false;
            }
            
            // Perform the relocations needed in the host process

            if (!PerformRelocations(peHeaders, baseAddress.AddrOfPinnedObject(), remoteDllAddress))
            {
                return false;
            }
            
            // Map the sections of the dll into the remote process

            if (!MapSections(peHeaders, baseAddress.AddrOfPinnedObject(), remoteDllAddress))
            {
                return false;
            }
            
            // Map the tls entries of the dll into the remote process

            if (!MapTlsEntries(peHeaders, baseAddress.AddrOfPinnedObject()))
            {
                return false;
            }
            
            // Call the entry point of the dll in the remote process

            var dllEntryPointAddress = remoteDllAddress + (int) peHeaders.ImageNtHeaders.OptionalHeader.AddressOfEntryPoint;

            if (!CallEntryPoint(remoteDllAddress, dllEntryPointAddress))
            {
                return false;
            }
            
            // Unpin the dll bytes from the memory of the host process
            
            baseAddress.Free();
            
            return true;
        }

        private bool CallEntryPoint(IntPtr baseAddress, IntPtr entryPoint)
        {
            // Get the id of the process

            var processId = _process.Id;
            
            // Open a handle to the process

            var processHandle = _process.SafeHandle;
            
            // Determine if the process is running under WOW64

            IsWow64Process(processHandle, out var isWow64);
            
            // Create shellcode to call the entry of the dll in the process

            var shellcode = isWow64 ? Shellcode.CallDllMainx86(baseAddress, entryPoint) : Shellcode.CallDllMainx64(baseAddress, entryPoint);
            
            // Allocate memory for the shellcode in the process

            var shellcodeSize = shellcode.Length;

            var shellcodeAddress = _memoryModule.AllocateMemory(processId, shellcodeSize);

            if (shellcodeAddress == IntPtr.Zero)
            {
                return false;
            }
            
            // Write the shellcode into the memory of the process

            if (!_memoryModule.WriteMemory(processId, shellcodeAddress, shellcode))
            {
                return false;
            }
            
            // Create a remote thread to call the entry point in the process
            
            RtlCreateUserThread(processHandle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, shellcodeAddress, IntPtr.Zero, out var remoteThreadHandle, 0);

            if (remoteThreadHandle is null)
            {
                return false;
            }
            
            // Wait for the remote thread to finish its task
            
            WaitForSingleObject(remoteThreadHandle, int.MaxValue);
            
            // Free the memory previously allocated for the shellcode

            if (!_memoryModule.FreeMemory(processId, shellcodeAddress))
            {
                return false;
            }
            
            // Close the handle opened to the process
            
            processHandle.Close();
            
            // Close the handle opened to the remote thread
            
            remoteThreadHandle.Close();
            
            return true;
        }
        
        private int GetSectionProtection(DataSectionFlags characteristics)
        {
            var protection = 0;
            
            // Determine the protection of the section

            if (characteristics.HasFlag(DataSectionFlags.MemoryNotCached))
            {
                protection |= (int) MemoryProtection.PageNoCache;
            }

            if (characteristics.HasFlag(DataSectionFlags.MemoryExecute))
            {
                if (characteristics.HasFlag(DataSectionFlags.MemoryRead))
                {
                    if (characteristics.HasFlag(DataSectionFlags.MemoryWrite))
                    {
                        protection |= (int) MemoryProtection.PageExecuteReadWrite;
                    }

                    else
                    {
                        protection |= (int) MemoryProtection.PageExecuteRead;
                    }
                }
                
                else if (characteristics.HasFlag(DataSectionFlags.MemoryWrite))
                {
                    protection |= (int) MemoryProtection.PageExecuteWriteCopy;
                }

                else
                {
                    protection |= (int) MemoryProtection.PageExecute;
                }
            }
            
            else if (characteristics.HasFlag(DataSectionFlags.MemoryRead))
            {
                if (characteristics.HasFlag(DataSectionFlags.MemoryWrite))
                {
                    protection |= (int) MemoryProtection.PageReadWrite;
                }

                else
                {
                    protection |= (int) MemoryProtection.PageReadOnly;
                }
            }
            
            else if (characteristics.HasFlag(DataSectionFlags.MemoryWrite))
            {
                protection |= (int) MemoryProtection.PageWriteCopy;
            }

            else
            {
                protection |= (int) MemoryProtection.PageNoAccess;
            }
            
            return protection;
        }
        
        private bool MapImports(PeFile peHeaders, IntPtr baseAddress)
        {
            // Get the dll imported functions

            var importedFunctions = peHeaders.ImportedFunctions;
            
            // Get the dll import descriptors

            var importDescriptors = peHeaders.ImageImportDescriptors;

            if (importDescriptors is null)
            {
                // No dll imports
                
                return true;
            }
            
            // Group the imported functions by the dll they reside in

            var groupedImportedFunctions = importedFunctions.GroupBy(importedFunction => importedFunction.DLL);

            var importDescriptorIndex = 0;

            // Get the e_lfanew value

            var eLfanew = peHeaders.ImageDosHeader.e_lfanew;
            
            foreach (var dll in groupedImportedFunctions)
            {
                // Get the virtual address of the imported function

                var functionVirtualAddress = Tools.RvaToVa(baseAddress, (int) eLfanew, (IntPtr) importDescriptors[importDescriptorIndex].FirstThunk);

                foreach (var importedFunction in dll)
                {
                    // Get the proc address of the imported function

                    var procAddress = GetProcAddress(GetModuleHandle(importedFunction.DLL), importedFunction.Name);
                    
                    // If the dll isn't already loaded into the host process

                    if (procAddress == IntPtr.Zero)
                    {
                        // Load the dll into the host process

                        if (LoadLibrary(importedFunction.DLL) is null)
                        {
                            return false;
                        }
                        
                        // Get the proc address of the imported function
                        
                        procAddress = GetProcAddress(GetModuleHandle(importedFunction.DLL), importedFunction.Name);
                    }
                    
                    // Map the imported function into the host process
                    
                    Marshal.WriteInt64(functionVirtualAddress, (long) procAddress);
                    
                    // Jump to the next functions virtual address

                    functionVirtualAddress += Marshal.SizeOf(typeof(IntPtr));
                }

                importDescriptorIndex += 1;
            }
            
            return true;
        }

        private bool MapSections(PeFile peHeaders, IntPtr baseAddress, IntPtr remoteAddress)
        {
            var processId = _process.Id;
            
            // Get the dll section headers

            var sectionHeaders = peHeaders.ImageSectionHeaders;

            foreach (var section in sectionHeaders)
            {
                // Get the protection of the section

                var sectionProtection = GetSectionProtection((DataSectionFlags) section.Characteristics);
                
                // Determine the address to map the section to in the process

                var sectionAddress = remoteAddress + (int) section.VirtualAddress;
                
                // Get the address of the raw data of the section in the host process

                var rawDataAddress = baseAddress + (int) section.PointerToRawData;
                
                // Get the size of the raw data of the section

                var rawDataSize = (int) section.SizeOfRawData;
                
                // Get the raw data of the section

                var rawData = new byte[rawDataSize];
                
                Marshal.Copy(rawDataAddress, rawData, 0, rawDataSize);
                
                // Map the section into the process

                if (!_memoryModule.WriteMemory(processId, sectionAddress, rawData))
                {
                    return false;
                }
                
                // Adjust the protection of the section in the process

                if (!_memoryModule.ProtectMemory(processId, sectionAddress, rawDataSize, sectionProtection))
                {
                    return false;
                }
            }
            
            return true;
        }
        
        private bool MapTlsEntries(PeFile peHeaders, IntPtr baseAddress)
        {
            // Get the tls directory of the dll

            var tlsDirectory = peHeaders?.ImageTlsDirectory;

            if (tlsDirectory is null)
            {
                // No tls directory
                
                return true;
            }
            
            // Call the entry point for each tls callback in the process

            return tlsDirectory.TlsCallbacks.All(callback => CallEntryPoint(baseAddress, (IntPtr) callback.Callback));
        }        
        
        private static bool PerformRelocations(PeFile peHeaders, IntPtr baseAddress, IntPtr remoteAddress)
        {
            // Determine if any relocations need to be performed

            if ((peHeaders.ImageNtHeaders.FileHeader.Characteristics & 0x01) > 0)
            {
                return true;
            }
            
            // Get the e_lfanew value

            var eLfanew = peHeaders.ImageDosHeader.e_lfanew;
            
            // Determine the image delta

            var imageDelta = (long) remoteAddress - (long) peHeaders.ImageNtHeaders.OptionalHeader.ImageBase;
            
            // Get the relocation directory of the dll

            var relocationDirectory = peHeaders.ImageRelocationDirectory;

            foreach (var relocation in relocationDirectory)
            {
                // Get the base address of the relocations

                var relocationsBaseAddress = Tools.RvaToVa(baseAddress, (int) eLfanew, (IntPtr) relocation.VirtualAddress);

                foreach (var offset in relocation.TypeOffsets)
                {
                    // Get the address of the relocation

                    var relocationAddress = relocationsBaseAddress + offset.Offset;

                    switch (offset.Type)
                    {
                        case 3:
                        {
                            // If the relocation is High Low

                            var value = Tools.PointerToStructure<int>(relocationAddress) + (int) imageDelta;
                            
                            // Perform the relocation
                            
                            Marshal.WriteInt32(relocationAddress, value);

                            break;
                        }

                        case 10:
                        {
                            // If the relocation is Dir64

                            var value = Tools.PointerToStructure<long>(relocationAddress) + imageDelta;
                            
                            // Perform the relocation
                            
                            Marshal.WriteInt64(relocationAddress, value);
                            
                            break;
                        }
                    }
                }
            }
            
            return true;
        }
    }
}