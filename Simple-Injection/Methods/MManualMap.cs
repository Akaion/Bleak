using System;
using PeNet;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using static Simple_Injection.Etc.Native;
using static Simple_Injection.Etc.Shellcode;
using static Simple_Injection.Etc.Tools;
using static Simple_Injection.Etc.Wrapper;

namespace Simple_Injection.Methods
{
    public static class MManualMap
    {   
        internal static bool Inject(string dllPath, string processName)
        {
            // Ensure both arguments passed in are valid
            
            if (string.IsNullOrEmpty(dllPath) || string.IsNullOrEmpty(processName))
            {
                return false;
            }
            
            // Ensure the dll exists

            if (!File.Exists(dllPath))
            {
                return false;
            }
            
            // Cache an instance of the specified process

            Process process;
            
            try
            {
                process = Process.GetProcessesByName(processName)[0];
            }

            catch (IndexOutOfRangeException)
            {
                return false;
            }
            
            // Get the handle of the specified process

            var processHandle = process.SafeHandle;

            if (processHandle == null)
            {
                return false;
            }
            
            // Get the pe headers
            
            var peHeaders = new PeFile(dllPath);
            
            if (peHeaders.Is64Bit)
            {
                return false;
            }
            
            // Get the dll bytes
            
            var dllBytes = File.ReadAllBytes(dllPath);

            // Pin the dll bytes
            
            var baseAddress = GCHandle.Alloc(dllBytes, GCHandleType.Pinned);
            
            // Allocate memory in process

            var remoteAddress = VirtualAllocEx(processHandle, IntPtr.Zero, (int) peHeaders.ImageNtHeaders.OptionalHeader.SizeOfImage, MemoryAllocation.AllAccess, MemoryProtection.PageExecuteReadWrite);
            
            // Map the imports

            if (!MapImports(peHeaders, baseAddress.AddrOfPinnedObject()))
            {
                return false;
            }

            // Map the relocations

            if (!MapRelocations(peHeaders, baseAddress.AddrOfPinnedObject(), remoteAddress))
            {
                return false;
            }

            // Map the sections

            if (!MapSections(peHeaders, processHandle, baseAddress.AddrOfPinnedObject(), remoteAddress))
            {
                return false;
            }

            // Map the tls entries

            if (!MapTlsEntries(peHeaders, processHandle, baseAddress.AddrOfPinnedObject()))
            {
                return false;
            }
            
            // Call the entry point

            var dllEntryPoint = remoteAddress + (int) peHeaders.ImageNtHeaders.OptionalHeader.AddressOfEntryPoint;

            if (!CallEntryPoint(processHandle, remoteAddress, dllEntryPoint))
            {
                return false;
            }
            
            // Unpin the dll bytes
            
            baseAddress.Free();
            
            return true;
        }  

        internal static bool Inject(string dllPath, int processId)
        {
            // Ensure both arguments passed in are valid
            
            if (string.IsNullOrEmpty(dllPath) || processId == 0)
            {
                return false;
            }
            
            // Ensure the dll exists

            if (!File.Exists(dllPath))
            {
                return false;
            }
            
            // Cache an instance of the specified process

            Process process;
            
            try
            {
                process = Process.GetProcessById(processId);
            }

            catch (IndexOutOfRangeException)
            {
                return false;
            }
            
            // Get the handle of the specified process

            var processHandle = process.SafeHandle;

            if (processHandle == null)
            {
                return false;
            }
            
            // Get the pe headers
            
            var peHeaders = new PeFile(dllPath);
            
            if (peHeaders.Is64Bit)
            {
                return false;
            }
            
            // Get the dll bytes
            
            var dllBytes = File.ReadAllBytes(dllPath);

            // Pin the dll bytes
            
            var baseAddress = GCHandle.Alloc(dllBytes, GCHandleType.Pinned);
            
            // Allocate memory in process

            var remoteAddress = VirtualAllocEx(processHandle, IntPtr.Zero, (int) peHeaders.ImageNtHeaders.OptionalHeader.SizeOfImage, MemoryAllocation.AllAccess, MemoryProtection.PageExecuteReadWrite);
            
            // Map the imports

            if (!MapImports(peHeaders, baseAddress.AddrOfPinnedObject()))
            {
                return false;
            }

            // Map the relocations

            if (!MapRelocations(peHeaders, baseAddress.AddrOfPinnedObject(), remoteAddress))
            {
                return false;
            }

            // Map the sections

            if (!MapSections(peHeaders, processHandle, baseAddress.AddrOfPinnedObject(), remoteAddress))
            {
                return false;
            }

            // Map the tls entries

            if (!MapTlsEntries(peHeaders, processHandle, baseAddress.AddrOfPinnedObject()))
            {
                return false;
            }
            
            // Call the entry point

            var dllEntryPoint = remoteAddress + (int) peHeaders.ImageNtHeaders.OptionalHeader.AddressOfEntryPoint;

            if (!CallEntryPoint(processHandle, remoteAddress, dllEntryPoint))
            {
                return false;
            }
            
            // Unpin the dll bytes
            
            baseAddress.Free();
            
            return true;
        }
        
        private static void LoadModuleIntoHost(string dllName)
        {
            // Create the dll path
            
            var dllPath = @"C:\Windows\System32\" + dllName.ToLower();

            // Load the dll into the host process
            
            MRtlCreateUserThread.Inject(dllPath, Process.GetCurrentProcess().Id);
        }
        
        private static IntPtr RvaToVa(IntPtr baseAddress, int eLfanew, IntPtr rva)
        {
            // Convert the relative virtual address to a virtual address
            
            return ImageRvaToVa(baseAddress + eLfanew, baseAddress, rva, IntPtr.Zero);
        }
        
        private static bool MapImports(PeFile peHeaders, IntPtr baseAddress)
        {
            // Get the pe headers

            var eLfanew = (int) peHeaders.ImageDosHeader.e_lfanew;
            
            // Get the imports
            
            var imports = peHeaders.ImportedFunctions;

            // Get the import descriptors

            var importDescriptors = peHeaders.ImageImportDescriptors;

            if (importDescriptors == null)
            {
                // No imports
                
                return true;
            }
            
            // Sort the imports by their dll
            
            var sortedImports = imports.GroupBy(import => import.DLL);

            // Map the imports
            
            var descriptorIndex = 0;
            
            foreach (var dll in sortedImports)
            {
                // Get the function data virtual address
                
                var functionDataAddress = RvaToVa(baseAddress, eLfanew, (IntPtr) importDescriptors[descriptorIndex].FirstThunk);
                
                foreach (var import in dll)
                {
                    // Get the proc address
                    
                    var procAddress = GetProcAddress(GetModuleHandle(import.DLL), import.Name);

                    // If the dll isn't already loaded into the host process
                    
                    if (procAddress == IntPtr.Zero)
                    {
                        // Load the dll into the host process
                        
                        LoadModuleIntoHost(import.DLL);
                        
                        // Get the proc address
                        
                        procAddress = GetProcAddress(GetModuleHandle(import.DLL), import.Name);
                    }
                    
                    // Map the import
                    
                    Marshal.WriteInt32(functionDataAddress, procAddress.ToInt32());

                    // Next function data virtual address
                    
                    functionDataAddress += Marshal.SizeOf(typeof(ImageThunkData));
                }
                
                descriptorIndex += 1;
            }

            return true;
        }
        
        private static bool MapRelocations(PeFile peHeaders, IntPtr baseAddress, IntPtr remoteAddress)
        {
            // Check if any relocations need to be mapped
            
            if ((peHeaders.ImageNtHeaders.FileHeader.Characteristics & 0x01) > 0)
            {
                return true;
            }
            
            var eLfanew = (int) peHeaders.ImageDosHeader.e_lfanew;
            
            // Calculate the base delta

            var baseDelta = remoteAddress - (int) peHeaders.ImageNtHeaders.OptionalHeader.ImageBase;
            
            // Get the relocation directory
            
            var relocationDirectory = peHeaders.ImageRelocationDirectory;
            
            var index = 0;

            while (index < relocationDirectory.Length)
            {
                // Get the real relocation directory address
            
                var relocationDirectoryAddress = RvaToVa(baseAddress, eLfanew, (IntPtr) relocationDirectory[index].VirtualAddress);
                
                foreach (var offset in relocationDirectory[index].TypeOffsets)
                {
                    var address = relocationDirectoryAddress + offset.Offset;

                    var value = PointerToStructure<uint>(address);
                    
                    switch (offset.Type)
                    {
                        case 1:
                        {
                            // Based High

                            value += (ushort) (((uint) baseDelta >> 16) & 65535);
                            
                            Marshal.WriteInt16(address, (short) value);
                            
                            break;
                        }
                            
                        case 2:
                        {
                            // Based Low
                            
                            value += (ushort) ((uint) baseDelta & 65535);
                            
                            Marshal.WriteInt16(address, (short) value);
                            
                            break;
                        }
                            
                        case 3:
                        {
                            // Based High Low

                            value += (uint) baseDelta;
                            
                            Marshal.WriteInt32(address, (int) value);
                            
                            break;
                        }
                            
                        case 10:
                        {
                            // Based Dir64
                            
                            value += (uint) baseDelta;
                            
                            Marshal.WriteInt32(address, (int) value);
                            
                            break;
                        }
                    }
                }

                index += 1;
            }

            return true;
        }

        private static int GetSectionProtection(DataSectionFlags characteristics)
        {
            var result = 0;

            if (characteristics.HasFlag(DataSectionFlags.MemoryNotCached))
            {
                // PageNoCache
                
                result |= 0x200;
            }

            if (characteristics.HasFlag(DataSectionFlags.MemoryExecute))
            {
                if (characteristics.HasFlag(DataSectionFlags.MemoryRead))
                {
                    if (characteristics.HasFlag(DataSectionFlags.MemoryWrite))
                    {
                        // PageExecuteReadWrite
                        
                        result |= 0x40;
                    }

                    else
                    { 
                        // PageExecuteRead
                        
                        result |= 0x20;
                    }
                        
                }
                
                else if (characteristics.HasFlag(DataSectionFlags.MemoryWrite))
                {
                    // PageExecuteWriteCopy
                    
                    result |= 0x80;
                }

                else
                {
                    // PageExecute
                    
                    result |= 0x10;
                }
            }
            
            else if (characteristics.HasFlag(DataSectionFlags.MemoryRead))
            {
                if (characteristics.HasFlag(DataSectionFlags.MemoryWrite))
                {
                    // PageReadWrite
                    
                    result |= 0x04;
                }

                else
                {
                    // PageReadOnly
                    
                    result |= 0x02;
                }               
            }
            
            else if (characteristics.HasFlag(DataSectionFlags.MemoryWrite))
            {
                // PageWriteCopy

                result |= 0x08;
            }

            else
            {
                // PageNoAccess
                
                result |= 0x01;
            }

            return result;
        }
        
        private static bool MapSections(PeFile peHeaders, SafeHandle processHandle, IntPtr baseAddress, IntPtr remoteAddress)
        {   
            // Get the section headers

            var sectionHeaders = peHeaders.ImageSectionHeaders;

            foreach (var section in sectionHeaders)
            {
                // Get the sections protection
                
                var protection = GetSectionProtection((DataSectionFlags) section.Characteristics);

                // Get the sections address
                
                var sectionAddress = remoteAddress + (int) section.VirtualAddress;

                // Get the raw data address
                
                var rawDataAddress = baseAddress + (int) section.PointerToRawData;

                // Get the size of the raw data
                
                var rawDataSize = (int) section.SizeOfRawData;
                
                // Get the raw data
                
                var rawData = new byte[rawDataSize];

                Marshal.Copy(rawDataAddress, rawData, 0,  rawDataSize);
                
                // Map the section
                
                WriteMemory(processHandle, sectionAddress, rawData, protection);
            }

            return true;
        }

        private static bool MapTlsEntries(PeFile peHeaders, SafeHandle processHandle, IntPtr baseAddress)
        {
            // Get the tls callbacks

            PeNet.Structures.IMAGE_TLS_CALLBACK[] tlsCallbacks;
            
            try
            {
                 tlsCallbacks = peHeaders.ImageTlsDirectory.TlsCallbacks;
            }

            catch (NullReferenceException)
            {
                return true;
            }
            
            // Call the entry point for each tls callback
            
            foreach (var callback in tlsCallbacks)
            {
                if (!CallEntryPoint(processHandle, baseAddress, (IntPtr) callback.Callback))
                {
                    return false;
                }
            }

            return true;
        }

        private static bool CallEntryPoint(SafeHandle processHandle, IntPtr baseAddress, IntPtr entryPoint)
        {
            var shellcode = CallDllMainx86(baseAddress, entryPoint);
            
            // Create shellcode to call the entry point
            
            //var shellcode = CallDllMainx86(baseAddress, entryPoint);
            
            // Allocate memory for the shellcode
            
            var shellcodeSize = shellcode.Length;

            var shellcodeMemoryPointer = VirtualAllocEx(processHandle, IntPtr.Zero, shellcodeSize, MemoryAllocation.AllAccess, MemoryProtection.PageExecuteReadWrite);

            if (shellcodeMemoryPointer == IntPtr.Zero)
            {
                //return false;
            }

            if (!WriteMemory(processHandle, shellcodeMemoryPointer, shellcode))
            {
                return false;
            }
            
            // Create a remote thread to call the entry point in the specified process
            
            var remoteThreadHandle = CreateRemoteThread(processHandle, IntPtr.Zero, 0, shellcodeMemoryPointer, IntPtr.Zero, 0, IntPtr.Zero);
            
            if (remoteThreadHandle == IntPtr.Zero)
            {
                return false;
            }
            
            // Wait for the remote thread to finish

            WaitForSingleObject(remoteThreadHandle, int.MaxValue);
            
            // Free the previously allocated memory
            
            VirtualFreeEx(processHandle, shellcodeMemoryPointer, shellcodeSize, MemoryAllocation.Release);
                    
            // Close the previously opened handle

            CloseHandle(remoteThreadHandle);

            return true;
        }   
    }
}