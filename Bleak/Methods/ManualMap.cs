using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Bleak.Etc;
using Bleak.Services;

namespace Bleak.Methods
{
    internal class ManualMap : IDisposable
    {
        private readonly Properties _properties;
        
        internal ManualMap(Process process, string dllPath)
        {
            _properties = new Properties(process, dllPath);
        }
        
        public void Dispose()
        {
            _properties?.Dispose();
        }
        
        internal bool Inject()
        {
            // Get the bytes of the dll
            
            var dllBytes = File.ReadAllBytes(_properties.DllPath);
            
            // Pin the dll bytes in the memory of the host process
            
            var baseAddress = GCHandle.Alloc(dllBytes, GCHandleType.Pinned);
            
            // Allocate memory for the dll in the remote process
            
            var dllSize = _properties.PeHeaders.ImageNtHeaders.OptionalHeader.SizeOfImage;
            
            var remoteDllAddress = _properties.MemoryModule.AllocateMemory(_properties.ProcessId, (int) dllSize);
            
            // Map the imports of the dll into the host process
            
            MapImports(baseAddress.AddrOfPinnedObject());
            
            // Perform the relocations needed in the host process
            
            PerformRelocations(baseAddress.AddrOfPinnedObject(), remoteDllAddress);
            
            // Map the sections of the dll into the remote process
            
            MapSections(baseAddress.AddrOfPinnedObject(), remoteDllAddress);
            
            // Map the tls entries of the dll into the remote process
            
            MapTlsEntries(baseAddress.AddrOfPinnedObject());
            
            // Call the entry point of the dll in the remote process
            
            var dllEntryPointAddress = remoteDllAddress + (int) _properties.PeHeaders.ImageNtHeaders.OptionalHeader.AddressOfEntryPoint;
            
            CallEntryPoint(remoteDllAddress, dllEntryPointAddress);
            
            // Unpin the dll bytes from the memory of the host process
            
            baseAddress.Free();
            
            return true;
        }
        
        private void CallEntryPoint(IntPtr baseAddress, IntPtr entryPoint)
        {
            // Initialize shellcode to call the entry of the dll in the remote process
            
            var shellcodeBytes = _properties.IsWow64 ? Shellcode.CallDllMainx86(baseAddress, entryPoint) : Shellcode.CallDllMainx64(baseAddress, entryPoint);
            
            // Allocate memory for the shellcode in the remote process
            
            var shellcodeAddress = IntPtr.Zero;
            
            try
            {
                shellcodeAddress = _properties.MemoryModule.AllocateMemory(_properties.ProcessId, shellcodeBytes.Length);
            }
            
            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to allocate memory for the shellcode in the remote process");
            }
            
            // Write the shellcode into the memory of the remote process
            
            try
            {
                _properties.MemoryModule.WriteMemory(_properties.ProcessId, shellcodeAddress, shellcodeBytes);
            }
            
            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to write the shellcode into the memory of the remote process");   
            }
            
            // Create a remote thread to call the entry point in the remote process
            
            Native.NtCreateThreadEx(out var remoteThreadHandle, Native.AccessMask.SpecificRightsAll | Native.AccessMask.StandardRightsAll, IntPtr.Zero, _properties.ProcessHandle, shellcodeAddress, IntPtr.Zero, Native.CreationFlags.HideFromDebugger, 0, 0, 0, IntPtr.Zero);
            
            if (remoteThreadHandle is null)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to create a remote thread to call the entry point in the remote process");
            }
            
            // Wait for the remote thread to finish its task
            
            Native.WaitForSingleObject(remoteThreadHandle, int.MaxValue);
            
            // Free the memory previously allocated for the shellcode in the remote process
            
            try
            {
                _properties.MemoryModule.FreeMemory(_properties.ProcessId, shellcodeAddress);
            }
            
            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to free the memory allocated for the shellcode in the remote process");   
            }
            
            // Close the handle opened to the remote thread
            
            remoteThreadHandle?.Close();
        }
        
        private int GetSectionProtection(Native.DataSectionFlags characteristics)
        {
            var protection = 0;
            
            // Determine the protection of the section
            
            if (characteristics.HasFlag(Native.DataSectionFlags.MemoryNotCached))
            {
                protection |= (int) Native.MemoryProtection.NoCache;
            }
            
            if (characteristics.HasFlag(Native.DataSectionFlags.MemoryExecute))
            {
                if (characteristics.HasFlag(Native.DataSectionFlags.MemoryRead))
                {
                    if (characteristics.HasFlag(Native.DataSectionFlags.MemoryWrite))
                    {
                        protection |= (int) Native.MemoryProtection.ExecuteReadWrite;
                    }
                    
                    else
                    {
                        protection |= (int) Native.MemoryProtection.ExecuteRead;
                    }
                }
                
                else if (characteristics.HasFlag(Native.DataSectionFlags.MemoryWrite))
                {
                    protection |= (int) Native.MemoryProtection.ExecuteWriteCopy;
                }
                
                else
                {
                    protection |= (int) Native.MemoryProtection.Execute;
                }
            }
            
            else if (characteristics.HasFlag(Native.DataSectionFlags.MemoryRead))
            {
                if (characteristics.HasFlag(Native.DataSectionFlags.MemoryWrite))
                {
                    protection |= (int) Native.MemoryProtection.ReadWrite;
                }
                
                else
                {
                    protection |= (int) Native.MemoryProtection.ReadOnly;
                }
            }
            
            else if (characteristics.HasFlag(Native.DataSectionFlags.MemoryWrite))
            {
                protection |= (int) Native.MemoryProtection.WriteCopy;
            }
            
            else
            {
                protection |= (int) Native.MemoryProtection.NoAccess;
            }
            
            return protection;
        }
        
        private void MapImports(IntPtr baseAddress)
        {
            // Get the import descriptors from the pe headers of the dll
            
            var importDescriptors = _properties.PeHeaders.ImageImportDescriptors;
            
            if (importDescriptors is null)
            {
                // No dll imports
                
                return;
            }
            
            // Group the imported functions by the dll they reside in
            
            var groupedImportedFunctions = _properties.PeHeaders.ImportedFunctions.GroupBy(importedFunction => importedFunction.DLL);
            
            var importDescriptorIndex = 0;
            
            foreach (var dll in groupedImportedFunctions)
            {
                // Get the virtual address of the imported function
                
                var functionVirtualAddress = Tools.RvaToVa(baseAddress, (int) _properties.PeHeaders.ImageDosHeader.e_lfanew, (IntPtr) importDescriptors[importDescriptorIndex].FirstThunk);
                
                foreach (var importedFunction in dll)
                {
                    var tempDllName = importedFunction.DLL;
                    
                    if (importedFunction.DLL.Contains("-ms-win-crt-"))
                    {
                        tempDllName = "ucrtbase.dll";
                    }
                    
                    // Get the address of the imported function
                    
                    var procAddress = Tools.GetRemoteProcAddress(_properties, tempDllName, importedFunction.Name);
                    
                    // If the dll isn't already loaded into the remote process
                    
                    if (procAddress == IntPtr.Zero)
                    {
                        // Get the path of the system dll
                        
                        var dllPath = Path.Combine(Environment.GetFolderPath(_properties.IsWow64 ? Environment.SpecialFolder.SystemX86 : Environment.SpecialFolder.System), tempDllName);
                        
                        // Get the proc address of the imported function
                        
                        new Injector().NtCreateThreadEx(_properties.ProcessId, dllPath);
                         
                        procAddress = Tools.GetRemoteProcAddress(_properties, tempDllName, importedFunction.Name);
                    }
                    
                    // Map the imported function into the host process
                    
                    Marshal.WriteInt64(functionVirtualAddress, (long) procAddress);
                    
                    // Jump to the next functions virtual address
                    
                    if (_properties.IsWow64)
                    {
                        functionVirtualAddress += sizeof(int);
                    }
                    
                    else
                    {
                        functionVirtualAddress += sizeof(long);
                    }
                }
                
                importDescriptorIndex += 1;
            }
        }
        
        private void MapSections(IntPtr baseAddress, IntPtr remoteAddress)
        {
            // Get the section headers of the dll from the pe headers
            
            var sectionHeaders = _properties.PeHeaders.ImageSectionHeaders;
            
            foreach (var section in sectionHeaders)
            {
                // Get the protection of the section
                    
                var sectionProtection = GetSectionProtection((Native.DataSectionFlags) section.Characteristics);
                
                // Determine the address to map the section to in the remote process
                
                var sectionAddress = remoteAddress + (int) section.VirtualAddress;
                
                // Get the address of the raw data of the section in the host process
                
                var rawDataAddress = baseAddress + (int) section.PointerToRawData;
                
                // Get the size of the raw data of the section
                
                var rawDataSize = (int) section.SizeOfRawData;
                
                // Get the raw data of the section
                
                var rawData = new byte[rawDataSize];
                
                Marshal.Copy(rawDataAddress, rawData, 0, rawDataSize);
                
                // Map the section into the remote process
                
                try
                {
                    _properties.MemoryModule.WriteMemory(_properties.ProcessId, sectionAddress, rawData);
                }
                
                catch (Win32Exception)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to write a section into the remote process");
                }
                
                // Adjust the protection of the section in the remote process
                
                try
                {
                    _properties.MemoryModule.ProtectMemory(_properties.ProcessId, sectionAddress, rawDataSize, sectionProtection);
                }
                
                catch (Win32Exception)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to adjust the protection of a section in the remote process"); 
                }
            }
        }
        
        private void MapTlsEntries(IntPtr baseAddress)
        {
            // Get the tls directory of the dll from the pe headers
            
            var tlsDirectory = _properties.PeHeaders?.ImageTlsDirectory;
            
            if (tlsDirectory is null)
            {
                // No tls directory
                
                return;
            }
            
            // Call the entry point for each tls callback in the remote process
            
            foreach (var tlsCallback in tlsDirectory.TlsCallbacks)
            {
                CallEntryPoint(baseAddress, (IntPtr) tlsCallback.Callback);
            }
        }        
        
        private void PerformRelocations(IntPtr baseAddress, IntPtr remoteAddress)
        {
            // Determine if any relocations need to be performed
            
            if (_properties.PeHeaders.ImageNtHeaders.FileHeader.Characteristics % 2 == 1)
            {
                return;
            }
            
            // Determine the image delta
            
            var imageDelta = (long) remoteAddress - (long) _properties.PeHeaders.ImageNtHeaders.OptionalHeader.ImageBase;
            
            // Get the relocation directory of the dll from the pe headers
            
            var relocationDirectory = _properties.PeHeaders.ImageRelocationDirectory;
            
            foreach (var relocation in relocationDirectory)
            {
                // Get the base address of the relocations
                
                var relocationsBaseAddress = Tools.RvaToVa(baseAddress, (int) _properties.PeHeaders.ImageDosHeader.e_lfanew, (IntPtr) relocation.VirtualAddress);
                
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