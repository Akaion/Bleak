using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Bleak.Etc;
using Bleak.Services;

namespace Bleak.Extensions
{
    internal class UnlinkFromPeb : IDisposable
    {
        private readonly Properties _properties;
        
        internal UnlinkFromPeb(Process process, string dllPath)
        {
            _properties = new Properties(process, dllPath);
        }
        
        public void Dispose()
        {
            _properties?.Dispose();
        }
        
        internal bool Unlink()
        {
            // If the process is x86
            
            if (_properties.IsWow64)
            {
                // Allocate memory for a buffer to store the peb base address
                
                var pebBaseAddressBuffer = Marshal.AllocHGlobal(sizeof(ulong));
                
                // Query the process and store the peb base address in the buffer
                
                Native.NtQueryInformationProcess(_properties.ProcessHandle, (int) Native.ProcessInformationClass.ProcessWow64Information, pebBaseAddressBuffer, sizeof(ulong), 0);
                
                // Get the peb base address from the buffer

                var pebBaseAddress = (IntPtr) Tools.PointerToStructure<ulong>(pebBaseAddressBuffer);

                // Read the process environment block from the remote process
                
                var peb = default(Native.Peb);
                
                try
                {
                    peb = _properties.MemoryModule.ReadMemory<Native.Peb>(_properties.ProcessId, pebBaseAddress);
                }
                
                catch (Win32Exception)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to read the process environment block of the remote process");
                }
                
                // Read the process environment block loader data from the remote process
                
                var pebLoaderData = default(Native.PebLdrData);
                
                try
                {
                    pebLoaderData = _properties.MemoryModule.ReadMemory<Native.PebLdrData>(_properties.ProcessId, (IntPtr) peb.Ldr);
                }
                
                catch (Win32Exception)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to read the process environment block's loader data of the remote process");
                }
                
                // Get the address of the first dll entry in the remote processes module list
                
                var currentEntry = pebLoaderData.InLoadOrderModuleList.Flink;
                
                // Get the address of the last dll entry in the remote processes module list
                
                var lastEntry = pebLoaderData.InLoadOrderModuleList.Blink;
                
                while (true)
                {
                    // Read the information about the current dll entry
                    
                    var dllEntry = default(Native.LdrDataTableEntry);
                    
                    try
                    {
                        dllEntry = _properties.MemoryModule.ReadMemory<Native.LdrDataTableEntry>(_properties.ProcessId, (IntPtr) currentEntry);
                    }
                    
                    catch (Win32Exception)
                    {
                        ExceptionHandler.ThrowWin32Exception("Failed to read the information of a dll entry");
                    }
                    
                    // Read the full dll name of the current dll entry
                    
                    var dllEntryNameBytes = new byte[0];
                    
                    try
                    {
                        dllEntryNameBytes = _properties.MemoryModule.ReadMemory(_properties.ProcessId, (IntPtr) dllEntry.FullDllName.Buffer, dllEntry.FullDllName.Length);
                    }
                    
                    catch (Win32Exception)
                    {
                        ExceptionHandler.ThrowWin32Exception("Failed to read the dll path of a dll entry");
                    }
                    
                    var ldrEntryName = Encoding.UTF8.GetString(dllEntryNameBytes).Replace("\0", "");
                    
                    if (string.Equals(_properties.DllPath, ldrEntryName, StringComparison.OrdinalIgnoreCase))
                    {
                        // Unlink the dll from the necessary linked lists
                        
                        UnlinkModule(dllEntry.InLoadOrderLinks);
                        
                        UnlinkModule(dllEntry.InMemoryOrderLinks);
                        
                        UnlinkModule(dllEntry.InInitOrderLinks);
                        
                        // Create a buffer to write over the base dll name buffer with
                        
                        var baseDllNameBuffer = new byte[dllEntry.BaseDllName.MaxLength];
                        
                        // Create a buffer to write over the full dll name buffer with
                        
                        var fullDllNameBuffer = new byte[dllEntry.FullDllName.MaxLength];
                        
                        // Create a buffer to write over the entry with
                        
                        var ldrDataTableEntrySize = Marshal.SizeOf(typeof(Native.LdrDataTableEntry64));
                        
                        var currentEntryBuffer = new byte[ldrDataTableEntrySize];
                        
                        // Write over the base dll name buffer with the new buffer
                        
                        try
                        {
                            _properties.MemoryModule.WriteMemory(_properties.ProcessId, (IntPtr) dllEntry.BaseDllName.Buffer, baseDllNameBuffer);
                        }
                        
                        catch (Win32Exception)
                        {
                            ExceptionHandler.ThrowWin32Exception("Failed to write over the dll name buffer");
                        }
                        
                        // Write over the full dll name buffer with the new buffer
                        
                        try
                        {
                            _properties.MemoryModule.WriteMemory(_properties.ProcessId, (IntPtr) dllEntry.FullDllName.Buffer, fullDllNameBuffer);
                        }
                        
                        catch (Win32Exception)
                        {
                            ExceptionHandler.ThrowWin32Exception("Failed to write over the dll path buffer");
                        }
                        
                        // Write over the dll entry with the new buffer
                        
                        try
                        {
                            _properties.MemoryModule.WriteMemory(_properties.ProcessId, (IntPtr) currentEntry, currentEntryBuffer);
                        }
                        
                        catch (Win32Exception)
                        {
                            ExceptionHandler.ThrowWin32Exception("Failed to write over the dll entry");
                        }
                        
                        break;
                    }
                    
                    if (currentEntry == lastEntry)
                    {
                        // The dll wasn't found in the process environment block
                        
                        var dllName = Path.GetFileName(_properties.DllPath);
                        
                        throw new ArgumentException($"No entry with the name {dllName} was found in the process environment block");
                    }
                    
                    // Jump to the next entry
                    
                    currentEntry = dllEntry.InLoadOrderLinks.Flink;
                }
                
                // Free the memory previously allocated for the buffer
                
                Marshal.FreeHGlobal(pebBaseAddressBuffer);
            }

            // If the process is x64
            
            else
            {
                var pbiSize = Marshal.SizeOf(typeof(Native.ProcessBasicInformation));
            
                // Allocate memory for a buffer to store the process basic information
                
                var pbiBuffer = Marshal.AllocHGlobal(pbiSize);
                
                // Query the process and store the process basic information in the buffer
                
                Native.NtQueryInformationProcess(_properties.ProcessHandle, (int) Native.ProcessInformationClass.ProcessBasicInformation, pbiBuffer, pbiSize, 0);
                
                // Read the process basic information from the buffer
                
                var pbi = Tools.PointerToStructure<Native.ProcessBasicInformation>(pbiBuffer);
                
                if (pbi.Equals(default(Native.ProcessBasicInformation)))
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to query the memory of the remote process");
                }
                
                // Read the process environment block from the remote process
                
                var peb = default(Native.Peb64);
                
                try
                {
                    peb = _properties.MemoryModule.ReadMemory<Native.Peb64>(_properties.ProcessId, pbi.PebBaseAddress);
                }
                
                catch (Win32Exception)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to read the process environment block of the remote process");
                }
                
                // Read the process environment block loader data from the remote process
                
                var pebLoaderData = default(Native.PebLdrData64);
                
                try
                {
                    pebLoaderData = _properties.MemoryModule.ReadMemory<Native.PebLdrData64>(_properties.ProcessId, (IntPtr) peb.Ldr);
                }
                
                catch (Win32Exception)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to read the process environment block's loader data of the remote process");
                }
                
                // Get the address of the first dll entry in the remote processes module list
                
                var currentEntry = pebLoaderData.InLoadOrderModuleList.Flink;
                
                // Get the address of the last dll entry in the remote processes module list
                
                var lastEntry = pebLoaderData.InLoadOrderModuleList.Blink;
                
                while (true)
                {
                    // Read the information about the current dll entry
                    
                    var dllEntry = default(Native.LdrDataTableEntry64);
                    
                    try
                    {
                        dllEntry = _properties.MemoryModule.ReadMemory<Native.LdrDataTableEntry64>(_properties.ProcessId, (IntPtr) currentEntry);
                    }
                    
                    catch (Win32Exception)
                    {
                        ExceptionHandler.ThrowWin32Exception("Failed to read the information of a dll entry");
                    }
                    
                    // Read the full dll name of the current dll entry
                    
                    var dllEntryNameBytes = new byte[0];
                    
                    try
                    {
                        dllEntryNameBytes = _properties.MemoryModule.ReadMemory(_properties.ProcessId, (IntPtr) dllEntry.FullDllName.Buffer, dllEntry.FullDllName.Length);
                    }
                    
                    catch (Win32Exception)
                    {
                        ExceptionHandler.ThrowWin32Exception("Failed to read the dll path of a dll entry");
                    }
                    
                    var ldrEntryName = Encoding.UTF8.GetString(dllEntryNameBytes).Replace("\0", "");
                    
                    if (string.Equals(_properties.DllPath, ldrEntryName, StringComparison.OrdinalIgnoreCase))
                    {
                        // Unlink the dll from the necessary linked lists
                        
                        UnlinkModule64(dllEntry.InLoadOrderLinks);
                        
                        UnlinkModule64(dllEntry.InMemoryOrderLinks);
                        
                        UnlinkModule64(dllEntry.InInitOrderLinks);
                        
                        // Create a buffer to write over the base dll name buffer with
                        
                        var baseDllNameBuffer = new byte[dllEntry.BaseDllName.MaxLength];
                        
                        // Create a buffer to write over the full dll name buffer with
                        
                        var fullDllNameBuffer = new byte[dllEntry.FullDllName.MaxLength];
                        
                        // Create a buffer to write over the entry with
                        
                        var ldrDataTableEntrySize = Marshal.SizeOf(typeof(Native.LdrDataTableEntry64));
                        
                        var currentEntryBuffer = new byte[ldrDataTableEntrySize];
                        
                        // Write over the base dll name buffer with the new buffer
                        
                        try
                        {
                            _properties.MemoryModule.WriteMemory(_properties.ProcessId, (IntPtr) dllEntry.BaseDllName.Buffer, baseDllNameBuffer);
                        }
                        
                        catch (Win32Exception)
                        {
                            ExceptionHandler.ThrowWin32Exception("Failed to write over the dll name buffer");
                        }
                        
                        // Write over the full dll name buffer with the new buffer
                        
                        try
                        {
                            _properties.MemoryModule.WriteMemory(_properties.ProcessId, (IntPtr) dllEntry.FullDllName.Buffer, fullDllNameBuffer);
                        }
                        
                        catch (Win32Exception)
                        {
                            ExceptionHandler.ThrowWin32Exception("Failed to write over the dll path buffer");
                        }
                        
                        // Write over the dll entry with the new buffer
                        
                        try
                        {
                            _properties.MemoryModule.WriteMemory(_properties.ProcessId, (IntPtr) currentEntry, currentEntryBuffer);
                        }
                        
                        catch (Win32Exception)
                        {
                            ExceptionHandler.ThrowWin32Exception("Failed to write over the dll entry");
                        }
                        
                        break;
                    }
                    
                    if (currentEntry == lastEntry)
                    {
                        // The dll wasn't found in the process environment block
                        
                        var dllName = Path.GetFileName(_properties.DllPath);
                        
                        throw new ArgumentException($"No entry with the name {dllName} was found in the process environment block");
                    }
                    
                    // Jump to the next entry
                    
                    currentEntry = dllEntry.InLoadOrderLinks.Flink;
                }
                
                // Free the memory previously allocated for the buffer
                
                Marshal.FreeHGlobal(pbiBuffer);
            }
            
            return true;
        }
        
        private void UnlinkModule(Native.ListEntry dllEntry)
        {
            // Get the previous dll entry
            
            var previousEntry = default(Native.ListEntry);
            
            try
            {
                previousEntry = _properties.MemoryModule.ReadMemory<Native.ListEntry>(_properties.ProcessId, (IntPtr) dllEntry.Blink);
            }
            
            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to read the previous dll entry of the dll entry");
            }
            
            // Change the front link of the previous dll entry to the front link of the dll entry
            
            previousEntry.Flink = dllEntry.Flink;
            
            // Write over the back link of the dll entry with the previous entry
            
            try
            {
                _properties.MemoryModule.WriteMemory(_properties.ProcessId, (IntPtr) dllEntry.Blink, previousEntry);
            }
            
            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to write over the back link of the dll entry with the previous entry");
            }
            
            // Get the next dll entry
            
            var nextEntry = default(Native.ListEntry);
            
            try
            {
                nextEntry = _properties.MemoryModule.ReadMemory<Native.ListEntry>(_properties.ProcessId, (IntPtr) dllEntry.Flink);
            }
            
            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to read the next dll entry of the dll entry");
            }
            
            // Change the back link of the next dll entry to the back link of the dll entry
            
            nextEntry.Blink = dllEntry.Blink;
            
            // Write over the front link of the dll entry with the next entry
            
            try
            {
                _properties.MemoryModule.WriteMemory(_properties.ProcessId, (IntPtr) dllEntry.Flink, nextEntry);
            }
            
            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to write over the front link of the dll entry with the next entry");
            }
        }
        
        private void UnlinkModule64(Native.ListEntry64 dllEntry)
        {
            // Get the previous dll entry
            
            var previousEntry = default(Native.ListEntry64);
            
            try
            {
                previousEntry = _properties.MemoryModule.ReadMemory<Native.ListEntry64>(_properties.ProcessId, (IntPtr) dllEntry.Blink);
            }
            
            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to read the previous dll entry of the dll entry");
            }
            
            // Change the front link of the previous dll entry to the front link of the dll entry
            
            previousEntry.Flink = dllEntry.Flink;
            
            // Write over the back link of the dll entry with the previous entry
            
            try
            {
                _properties.MemoryModule.WriteMemory(_properties.ProcessId, (IntPtr) dllEntry.Blink, previousEntry);
            }
            
            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to write over the back link of the dll entry with the previous entry");
            }
            
            // Get the next dll entry
            
            var nextEntry = default(Native.ListEntry64);
            
            try
            {
                nextEntry = _properties.MemoryModule.ReadMemory<Native.ListEntry64>(_properties.ProcessId, (IntPtr) dllEntry.Flink);
            }
            
            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to read the next dll entry of the dll entry");
            }
            
            // Change the back link of the next dll entry to the back link of the dll entry
            
            nextEntry.Blink = dllEntry.Blink;
            
            // Write over the front link of the dll entry with the next entry
            
            try
            {
                _properties.MemoryModule.WriteMemory(_properties.ProcessId, (IntPtr) dllEntry.Flink, nextEntry);
            }
            
            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to write over the front link of the dll entry with the next entry");
            }
        }
    }
}