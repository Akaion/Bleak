using Bleak.Handlers;
using Bleak.Native;
using Bleak.Tools.Objects;
using Bleak.Wrappers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Bleak.Tools
{
    internal static class NativeTools
    {
        internal static IEnumerable<Structures.ModuleEntry> GetProcessModules(int processId)
        {
            // Create a toolhelp snapshot for the target process

            var snapshotHandle = PInvoke.CreateToolhelp32Snapshot(Enumerations.ToolHelpSnapshotType.Module | Enumerations.ToolHelpSnapshotType.Module32, (uint) processId);

            if (snapshotHandle is null)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to create a toolhelp snapshot for the target process");
            }

            // Store a module entry structure in a buffer

            var moduleEntry = new Structures.ModuleEntry { Size = (uint) Marshal.SizeOf<Structures.ModuleEntry>() };

            var moduleEntryBuffer = MemoryTools.StoreStructureInBuffer(moduleEntry);

            // Get the first module loaded in the target process

            if (!PInvoke.Module32First(snapshotHandle, moduleEntryBuffer))
            {
                ExceptionHandler.ThrowWin32Exception("No modules were found loaded in the target process");
            }
            
            yield return Marshal.PtrToStructure<Structures.ModuleEntry>(moduleEntryBuffer);

            // Get the rest of the modules loaded in the target process

            while (PInvoke.Module32Next(snapshotHandle, moduleEntryBuffer))
            {
                yield return Marshal.PtrToStructure<Structures.ModuleEntry>(moduleEntryBuffer);
            }

            // Free the memory allocated for the buffer

            MemoryTools.FreeMemoryForBuffer(moduleEntryBuffer, Marshal.SizeOf<Structures.ModuleEntry>());

            snapshotHandle.Dispose();
        }

        internal static IntPtr GetFunctionAddress(PropertyWrapper propertyWrapper, string moduleName, string functionName)
        {
            // Look for the module in the target process

            var modules = GetProcessModules(propertyWrapper.Process.Id).Where(m => m.Module.Equals(moduleName, StringComparison.OrdinalIgnoreCase));

            // Get an instance of the module

            var systemPath = propertyWrapper.IsWow64Process.Value ? Environment.GetFolderPath(Environment.SpecialFolder.SystemX86) : Environment.GetFolderPath(Environment.SpecialFolder.System);

            var module = modules.FirstOrDefault(m => m.ExePath.StartsWith(systemPath, StringComparison.OrdinalIgnoreCase));

            if (module.Equals(default(Structures.ModuleEntry)))
            {
                return IntPtr.Zero;
            }

            if (!propertyWrapper.PeInstances.ContainsKey(module.Module))
            {
                propertyWrapper.PeInstances.Add(module.Module, new PeInstance(module.ExePath));
            }

            var peInstance = propertyWrapper.PeInstances[module.Module];

            // Look for the function in the exported functions of the module

            var function = peInstance.ExportedFunctions.FirstOrDefault(f => f.Name.Equals(functionName, StringComparison.OrdinalIgnoreCase));

            if (function.Equals(default(PortableExecutable.Objects.ExportedFunction)))
            {
                throw new ApplicationException($"Failed to find the function {functionName} in the exported functions of {moduleName}");
            }

            // Calculate the address of the function in the target process

            var functionAddress = (ulong) module.BaseAddress + function.Offset;

            // Calculate the start and end address of the modules export table

            ulong exportTableStartAddress;

            ulong exportTableEndAddress;

            if (propertyWrapper.IsWow64Process.Value)
            {
                var optionalHeader = peInstance.PeParser.GetPeHeaders().NtHeaders32.OptionalHeader;

                exportTableStartAddress = (ulong) module.BaseAddress + optionalHeader.DataDirectory[0].VirtualAddress;

                exportTableEndAddress = exportTableStartAddress + optionalHeader.DataDirectory[0].Size;
            }

            else
            {
                var optionalHeader = peInstance.PeParser.GetPeHeaders().NtHeaders64.OptionalHeader;

                exportTableStartAddress = (ulong) module.BaseAddress + optionalHeader.DataDirectory[0].VirtualAddress;

                exportTableEndAddress = exportTableStartAddress + optionalHeader.DataDirectory[0].Size;
            }

            // Check whether the function is forwarded to another function

            if (functionAddress >= exportTableStartAddress && functionAddress <= exportTableEndAddress)
            {
                var forwardedFunctionBytes = new List<byte>();

                // Read the bytes of the forwarded function from the target process

                while (true)
                {
                    var currentByte = propertyWrapper.MemoryManager.Value.ReadMemory((IntPtr) functionAddress, 1);

                    if (currentByte[0] == 0x00)
                    {
                        break;
                    }

                    forwardedFunctionBytes.Add(currentByte[0]);

                    functionAddress += 1;
                }

                var forwardedFunction = Encoding.Default.GetString(forwardedFunctionBytes.ToArray()).Split('.');

                // Get the name of the module the forwarded function is from

                var forwardedFunctionModuleName = forwardedFunction[0] + ".dll";

                // Get the name of forwarded function

                var forwardedFunctionName = forwardedFunction[1];

                // Get the address of the forwarded function

                return GetFunctionAddress(propertyWrapper, forwardedFunctionModuleName, forwardedFunctionName);
            }

            return (IntPtr) functionAddress;  
        }
    }
}
