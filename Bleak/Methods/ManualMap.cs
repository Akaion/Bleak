using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Bleak.Etc;
using Bleak.Services;
using Jupiter;
using PeNet;

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

            MapImports(peHeaders, baseAddress.AddrOfPinnedObject());
            
            // Perform the relocations needed in the host process

            PerformRelocations(peHeaders, baseAddress.AddrOfPinnedObject(), remoteDllAddress);
            
            // Map the sections of the dll into the remote process

            MapSections(peHeaders, baseAddress.AddrOfPinnedObject(), remoteDllAddress);
            
            // Map the tls entries of the dll into the remote process

            MapTlsEntries(peHeaders, baseAddress.AddrOfPinnedObject());
            
            // Call the entry point of the dll in the remote process

            var dllEntryPointAddress = remoteDllAddress + (int) peHeaders.ImageNtHeaders.OptionalHeader.AddressOfEntryPoint;

            CallEntryPoint(remoteDllAddress, dllEntryPointAddress);
            
            // Unpin the dll bytes from the memory of the host process
            
            baseAddress.Free();
            
            return true;
        }

        private void CallEntryPoint(IntPtr baseAddress, IntPtr entryPoint)
        {
            // Get the id of the process

            var processId = _process.Id;
            
            // Open a handle to the process

            var processHandle = _process.SafeHandle;
            
            // Determine if the process is running under WOW64

            Native.IsWow64Process(processHandle, out var isWow64);
            
            // Create shellcode to call the entry of the dll in the process

            var shellcodeBytes = isWow64 ? Shellcode.CallDllMainx86(baseAddress, entryPoint) : Shellcode.CallDllMainx64(baseAddress, entryPoint);
            
            // Allocate memory for the shellcode in the process

            var shellcodeSize = shellcodeBytes.Length;

            var shellcodeAddress = IntPtr.Zero;

            try
            {
                shellcodeAddress = _memoryModule.AllocateMemory(processId, shellcodeSize);
            }

            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to allocate memory for the shellcode in the process");
            }
            
            // Write the shellcode into the memory of the process

            try
            {
                _memoryModule.WriteMemory(processId, shellcodeAddress, shellcodeBytes);
            }

            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to write the shellcode into the memory of the process");   
            }
            
            // Create a remote thread to call the entry point in the process
            
            Native.RtlCreateUserThread(processHandle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, shellcodeAddress, IntPtr.Zero, out var remoteThreadHandle, 0);

            if (remoteThreadHandle is null)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to create a remote thread to call the entry point in the process");
            }
            
            // Wait for the remote thread to finish its task
            
            Native.WaitForSingleObject(remoteThreadHandle, int.MaxValue);
            
            // Free the memory previously allocated for the shellcode

            try
            {
                _memoryModule.FreeMemory(processId, shellcodeAddress);
            }

            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to free the memory allocated for the shellcode in the process");   
            }
            
            // Close the handle opened to the process
            
            processHandle?.Close();
            
            // Close the handle opened to the remote thread
            
            remoteThreadHandle?.Close();
        }
        
        private int GetSectionProtection(Native.DataSectionFlags characteristics)
        {
            var protection = 0;
            
            // Determine the protection of the section

            if (characteristics.HasFlag(Native.DataSectionFlags.MemoryNotCached))
            {
                protection |= (int) Native.MemoryProtection.PageNoCache;
            }

            if (characteristics.HasFlag(Native.DataSectionFlags.MemoryExecute))
            {
                if (characteristics.HasFlag(Native.DataSectionFlags.MemoryRead))
                {
                    if (characteristics.HasFlag(Native.DataSectionFlags.MemoryWrite))
                    {
                        protection |= (int) Native.MemoryProtection.PageExecuteReadWrite;
                    }

                    else
                    {
                        protection |= (int) Native.MemoryProtection.PageExecuteRead;
                    }
                }
                
                else if (characteristics.HasFlag(Native.DataSectionFlags.MemoryWrite))
                {
                    protection |= (int) Native.MemoryProtection.PageExecuteWriteCopy;
                }

                else
                {
                    protection |= (int) Native.MemoryProtection.PageExecute;
                }
            }
            
            else if (characteristics.HasFlag(Native.DataSectionFlags.MemoryRead))
            {
                if (characteristics.HasFlag(Native.DataSectionFlags.MemoryWrite))
                {
                    protection |= (int) Native.MemoryProtection.PageReadWrite;
                }

                else
                {
                    protection |= (int) Native.MemoryProtection.PageReadOnly;
                }
            }
            
            else if (characteristics.HasFlag(Native.DataSectionFlags.MemoryWrite))
            {
                protection |= (int) Native.MemoryProtection.PageWriteCopy;
            }

            else
            {
                protection |= (int) Native.MemoryProtection.PageNoAccess;
            }
            
            return protection;
        }
        
        private void MapImports(PeFile peHeaders, IntPtr baseAddress)
        {
            // Get the dll imported functions

            var importedFunctions = peHeaders.ImportedFunctions;
            
            // Get the dll import descriptors

            var importDescriptors = peHeaders.ImageImportDescriptors;

            if (importDescriptors is null)
            {
                // No dll imports
                
                return;
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

                    var procAddress = Native.GetProcAddress(Native.GetModuleHandle(importedFunction.DLL), importedFunction.Name);
                    
                    // If the dll isn't already loaded into the host process

                    if (procAddress == IntPtr.Zero)
                    {
                        // Load the dll into the host process

                        if (Native.LoadLibrary(importedFunction.DLL) is null)
                        {
                            ExceptionHandler.ThrowWin32Exception("Failed to load a dll import into the host process");
                        }
                        
                        // Get the proc address of the imported function
                        
                        procAddress = Native.GetProcAddress(Native.GetModuleHandle(importedFunction.DLL), importedFunction.Name);
                    }
                    
                    // Map the imported function into the host process
                    
                    Marshal.WriteInt64(functionVirtualAddress, (long) procAddress);
                    
                    // Jump to the next functions virtual address

                    functionVirtualAddress += Marshal.SizeOf(typeof(IntPtr));
                }

                importDescriptorIndex += 1;
            }
        }

        private void MapSections(PeFile peHeaders, IntPtr baseAddress, IntPtr remoteAddress)
        {
            var processId = _process.Id;
            
            // Get the dll section headers

            var sectionHeaders = peHeaders.ImageSectionHeaders;

            foreach (var section in sectionHeaders)
            {
                // Get the protection of the section

                var sectionProtection = GetSectionProtection((Native.DataSectionFlags) section.Characteristics);
                
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

                try
                {
                    _memoryModule.WriteMemory(processId, sectionAddress, rawData);
                }

                catch (Win32Exception)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to write a section into the process");
                }

                // Adjust the protection of the section in the process

                try
                {
                    _memoryModule.ProtectMemory(processId, sectionAddress, rawDataSize, sectionProtection);
                }

                catch (Win32Exception)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to adjust the protection of a section in the process"); 
                }
            }
        }
        
        private void MapTlsEntries(PeFile peHeaders, IntPtr baseAddress)
        {
            // Get the tls directory of the dll

            var tlsDirectory = peHeaders?.ImageTlsDirectory;

            if (tlsDirectory is null)
            {
                // No tls directory
                
                return;
            }
            
            // Call the entry point for each tls callback in the process

            foreach (var tlsCallback in tlsDirectory.TlsCallbacks)
            {
                CallEntryPoint(baseAddress, (IntPtr) tlsCallback.Callback);
            }
        }        
        
        private void PerformRelocations(PeFile peHeaders, IntPtr baseAddress, IntPtr remoteAddress)
        {
            // Determine if any relocations need to be performed

            if ((peHeaders.ImageNtHeaders.FileHeader.Characteristics & 0x01) > 0)
            {
                return;
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
        }
    }
}