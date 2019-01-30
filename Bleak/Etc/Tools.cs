using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using PeNet;

namespace Bleak.Etc
{
    internal static class Tools
    {
        internal static IEnumerable<Native.ModuleEntry> GetProcessModules(int processId)
        {
            var processModules = new List<Native.ModuleEntry>();
            
            // Create a tool help snapshot
            
            var snapshotHandle = Native.CreateToolhelp32Snapshot(Native.SnapshotFlags.Module | Native.SnapshotFlags.Module32, (uint) processId);
            
            // Initialize a module entry struct
            
            var moduleEntrySize = Marshal.SizeOf(typeof(Native.ModuleEntry));
            
            var moduleEntry = new Native.ModuleEntry { Size = (uint) moduleEntrySize};
            
            // Store the module entry struct in a buffer
            
            var moduleEntryBuffer = StructureToPointer(moduleEntry);
            
            // Get the first module of the process and store it in the buffer
            
            if (!Native.Module32First(snapshotHandle, moduleEntryBuffer))
            {
                return processModules;
            }
            
            // Get the first module entry structure from the buffer
            
            moduleEntry = PointerToStructure<Native.ModuleEntry>(moduleEntryBuffer);
            
            processModules.Add(moduleEntry);
            
            // Get the rest of the modules in the process
            
            while (Native.Module32Next(snapshotHandle, moduleEntryBuffer))
            {
                // Get the module entry structure from the buffer
                
                moduleEntry = PointerToStructure<Native.ModuleEntry>(moduleEntryBuffer);
                
                processModules.Add(moduleEntry);
            }
            
            return processModules;
        }
        
        internal static IntPtr GetRemoteProcAddress(Properties properties, string moduleName, string procName)
        {
            var modules = GetProcessModules(properties.ProcessId).Where(m => string.Equals(m.Module, moduleName, StringComparison.OrdinalIgnoreCase));

            Native.ModuleEntry module;

            // If the process ix x86

            if (properties.IsWow64)
            {
                var systemPath = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);

                module = modules.SingleOrDefault(m => m.ExePath.StartsWith(systemPath, StringComparison.OrdinalIgnoreCase));
            }

            // If the process is x64

            else
            {
                var systemPath = Environment.GetFolderPath(Environment.SpecialFolder.System);

                module = modules.SingleOrDefault(m => m.ExePath.StartsWith(systemPath, StringComparison.OrdinalIgnoreCase));
            }
            
            if (module.Equals(default(Native.ModuleEntry)))
            {
                // Failed to find the module
                
                return IntPtr.Zero;
            }
            
            // Get the pe headers of the module
            
            var peHeaders = new PeFile(module.ExePath);
            
            // Look for the function in the exported functions
            
            var function = peHeaders.ExportedFunctions.SingleOrDefault(f => string.Equals(f.Name, procName, StringComparison.OrdinalIgnoreCase));
            
            if (function is null)
            {
                // Failed to find the function in the dll
                
                return IntPtr.Zero;
            }
            
            // Add the function offset onto the base address of the module
            
            return (IntPtr) ((ulong) module.BaseAddress + function.Address);
        }
        
        internal static TStructure PointerToStructure<TStructure>(IntPtr address)
        {
            // Read the structure from memory at the address
            
            var structure = (TStructure) Marshal.PtrToStructure(address, typeof(TStructure));

            return structure;
        }     
        
        internal static IntPtr RvaToVa(IntPtr baseAddress, int eLfanew, IntPtr rva)
        {
            // Convert a relative virtual address to a virtual address

            return Native.ImageRvaToVa(baseAddress + eLfanew, baseAddress, rva, IntPtr.Zero);
        }
        
        internal static IntPtr StructureToPointer<TStructure>(TStructure structure)
        {
            var structureSize = Marshal.SizeOf(typeof(TStructure));

            // Allocate memory to store the structure
            
            var pointer = Marshal.AllocHGlobal(structureSize);
            
            // Store the structure in the allocated memory
            
            Marshal.StructureToPtr(structure, pointer, true);

            return pointer;
        }
    }
}