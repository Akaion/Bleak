using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Bleak.Etc;
using Bleak.Services;
using Jupiter;

namespace Bleak.Extensions
{
    internal class UnlinkFromPeb
    {
        private readonly MemoryModule _memoryModule;
        
        internal UnlinkFromPeb()
        {
            _memoryModule = new MemoryModule();
        }

        internal bool Unlink(Process process, string dllPath)
        {
            // Get the id of the process

            var processId = process.Id;
            
            // Get the size of the process basic information structure
            
            var pbiSize = Marshal.SizeOf(typeof(Native.ProcessBasicInformation));

            // Allocate memory for a buffer to store the process basic information
            
            var pbiBuffer = Marshal.AllocHGlobal(pbiSize);
            
            // Open a handle to the process
            
            var processHandle = process.SafeHandle;
            
            // Query the process and store the process basic information in the buffer
            
            Native.NtQueryInformationProcess(processHandle, 0, pbiBuffer, pbiSize, 0);
            
            // Read the process basic information from the buffer
            
            var pbi = Tools.PointerToStructure<Native.ProcessBasicInformation>(pbiBuffer);

            if (pbi.Equals(default(Native.ProcessBasicInformation)))
            {
                ExceptionHandler.ThrowWin32Exception("Failed to query the memory of the process");
            }
            
            // Read the process environment block from the process

            var peb = default(Native.Peb);

            try
            {
                peb = _memoryModule.ReadMemory<Native.Peb>(processId, pbi.PebBaseAddress);
            }

            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to read the process environment block of the process");
            }
            
            // Read the process environment block loader data from the process

            var pebLoaderData = default(Native.PebLdrData);

            try
            {
                pebLoaderData = _memoryModule.ReadMemory<Native.PebLdrData>(processId, peb.Ldr);
            }

            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to read the process environment block loader data of the process");
            }
            
            // Get the address of the first dll entry in the processes module list
            
            var currentEntry = pebLoaderData.InLoadOrderModuleList.Flink;

            // Get the address of the last dll entry in the processes module list
            
            var lastEntry = pebLoaderData.InLoadOrderModuleList.Blink;

            while (true)
            {
                // Read the information about the current dll entry

                var dllEntry = default(Native.LdrDataTableEntry);

                try
                {
                    dllEntry = _memoryModule.ReadMemory<Native.LdrDataTableEntry>(processId, currentEntry);
                }

                catch (Win32Exception)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to read the information of a dll entry");
                }
                
                // Read the full dll name of the current dll entry

                var dllEntryNameBytes = new byte[0];

                try
                {
                    dllEntryNameBytes = _memoryModule.ReadMemory(processId, dllEntry.FullDllName.Buffer, dllEntry.FullDllName.Length);
                }

                catch (Win32Exception)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to read the dll path of a dll entry");
                }
                
                var ldrEntryName = Encoding.UTF8.GetString(dllEntryNameBytes).Replace("\0", "");
                
                if (string.Equals(dllPath, ldrEntryName, StringComparison.OrdinalIgnoreCase))
                {
                    // Unlink the dll from the necessary links
                    
                    UnlinkModule(processId, dllEntry.InLoadOrderLinks);
                    
                    UnlinkModule(processId, dllEntry.InMemoryOrderLinks);
                    
                    UnlinkModule(processId, dllEntry.InInitOrderLinks);

                    // Create a buffer to write over the base dll name buffer with
                    
                    var baseDllNameBuffer = new byte[dllEntry.BaseDllName.MaxLength];
                    
                    // Create a buffer to write over the full dll name buffer with
                    
                    var fullDllNameBuffer = new byte[dllEntry.FullDllName.MaxLength];

                    // Create a buffer to write over the entry with
                    
                    var ldrDataTableEntrySize = Marshal.SizeOf(typeof(Native.LdrDataTableEntry));
                    
                    var currentEntryBuffer = new byte[ldrDataTableEntrySize];

                    // Write over the base dll name buffer with the new buffer

                    try
                    {
                        _memoryModule.WriteMemory(processId, dllEntry.BaseDllName.Buffer, baseDllNameBuffer);
                    }

                    catch (Win32Exception)
                    {
                        ExceptionHandler.ThrowWin32Exception("Failed to write over the dll name buffer");
                    }
                    
                    // Write over the full dll name buffer with the new buffer
                    
                    try
                    {
                        _memoryModule.WriteMemory(processId, dllEntry.FullDllName.Buffer, fullDllNameBuffer);
                    }

                    catch (Win32Exception)
                    {
                        ExceptionHandler.ThrowWin32Exception("Failed to write over the dll path buffer");
                    }
                    
                    // Write over the dll entry with the new buffer
                    
                    try
                    {
                        _memoryModule.WriteMemory(processId, currentEntry, currentEntryBuffer);
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
                    
                    var dllName = Path.GetFileName(dllPath);
                    
                    throw new ArgumentException($"No entry with the name {dllName} was found in the process environment block");
                }
                
                // Jump to the next entry
                
                currentEntry = dllEntry.InLoadOrderLinks.Flink;
            }
            
            // Free the memory previously allocated for the buffer
            
            Marshal.FreeHGlobal(pbiBuffer);
            
            // Close the handle opened to the process
            
            processHandle?.Close();
            
            return true;
        }
        
        private void UnlinkModule(int processId, Native.ListEntry dllEntry)
        {
            // Get the previous dll entry

            var previousEntry = default(Native.ListEntry);

            try
            {
                previousEntry = _memoryModule.ReadMemory<Native.ListEntry>(processId, dllEntry.Blink);
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
                _memoryModule.WriteMemory(processId, dllEntry.Blink, previousEntry);
            }

            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to write over the back link of the dll entry with the previous entry");
            }
            
            // Get the next dll entry

            var nextEntry = default(Native.ListEntry);

            try
            {
                nextEntry = _memoryModule.ReadMemory<Native.ListEntry>(processId, dllEntry.Flink);
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
                _memoryModule.WriteMemory(processId, dllEntry.Flink, nextEntry);
            }

            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to write over the front link of the dll entry with the next entry");
            }
        }
    }
}