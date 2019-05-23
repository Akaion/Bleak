using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Bleak.Assembly;
using Bleak.Handlers;
using Bleak.Memory;
using Bleak.Native;
using Bleak.RemoteProcess.Objects;
using Bleak.Shared;

namespace Bleak.RemoteProcess
{
    internal class ProcessWrapper : IDisposable
    {
        internal readonly bool IsWow64;

        internal readonly List<Module> Modules;

        internal readonly Process Process;

        private readonly Assembler _assembler;

        private readonly MemoryManager _memoryManager;

        internal ProcessWrapper(int processId)
        {
            Process = GetProcess(processId);

            IsWow64 = IsProcessWow64();

            Modules = new List<Module>();

            _assembler = new Assembler(IsWow64);

            _memoryManager = new MemoryManager(Process.SafeHandle);

            EnableDebuggerPrivileges();

            Modules.AddRange(GetProcessModules());
        }

        internal ProcessWrapper(string processName)
        {
            Process = GetProcess(processName);

            IsWow64 = IsProcessWow64();

            Modules = new List<Module>();

            _assembler = new Assembler(IsWow64);

            _memoryManager = new MemoryManager(Process.SafeHandle);

            EnableDebuggerPrivileges();

            Modules.AddRange(GetProcessModules());
        }

        public void Dispose()
        {
            foreach (var module in Modules)
            {
                module.Dispose();
            }

            Process.Dispose();
        }

        internal void CallFunction(CallingConvention callingConvention, IntPtr functionAddress, params ulong[] parameters)
        {
            // Write the shellcode used to call the function into the remote process

            var shellcode = _assembler.AssembleFunctionCall(callingConvention, functionAddress, IntPtr.Zero, parameters);

            var shellcodeBuffer = _memoryManager.AllocateVirtualMemory(shellcode.Length);

            _memoryManager.WriteVirtualMemory(shellcodeBuffer, shellcode);

            // Create a thread in the remote process to call the shellcode
            
            var ntStatus = PInvoke.RtlCreateUserThread(Process.SafeHandle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, shellcodeBuffer, IntPtr.Zero, out var threadHandle, out _);

            if (ntStatus != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to create a thread in the remote process");
            }

            PInvoke.WaitForSingleObject(threadHandle, int.MaxValue);

            threadHandle.Dispose();

            _memoryManager.FreeVirtualMemory(shellcodeBuffer);
        }
        
        internal TStructure CallFunction<TStructure>(CallingConvention callingConvention, IntPtr functionAddress, params ulong[] parameters) where TStructure : struct
        {
            // Allocate a buffer in the remote process to store the returned value of the function

            var returnBuffer = _memoryManager.AllocateVirtualMemory<TStructure>();

            // Write the shellcode used to call the function into the remote process

            var shellcode = _assembler.AssembleFunctionCall(callingConvention, functionAddress, returnBuffer, parameters);

            var shellcodeBuffer = _memoryManager.AllocateVirtualMemory(shellcode.Length);

            _memoryManager.WriteVirtualMemory(shellcodeBuffer, shellcode);

            // Create a thread in the remote process to call the shellcode
            
            var ntStatus = PInvoke.RtlCreateUserThread(Process.SafeHandle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, shellcodeBuffer, IntPtr.Zero, out var threadHandle, out _);

            if (ntStatus != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to create a thread in the remote process");
            }

            PInvoke.WaitForSingleObject(threadHandle, int.MaxValue);

            threadHandle.Dispose();

            _memoryManager.FreeVirtualMemory(shellcodeBuffer);

            try
            {
                // Read the returned value of the function from the buffer

                return _memoryManager.ReadVirtualMemory<TStructure>(returnBuffer);
            }

            finally
            {
                _memoryManager.FreeVirtualMemory(returnBuffer);
            }
        }

        internal TStructure CallFunction<TStructure>(CallingConvention callingConvention, string moduleName, string functionName, params ulong[] parameters) where TStructure : struct
        {
            // Get the address of the function in the remote process

            var functionAddress = GetFunctionAddress(moduleName, functionName);

            // Call the function in the remote process

            return CallFunction<TStructure>(callingConvention, functionAddress, parameters);
        }

        internal IntPtr GetFunctionAddress(string moduleName, string functionName)
        {
            // Look for the module in the module list of the remote process

            var processModule = Modules.Find(module => module.Name.Equals(moduleName, StringComparison.OrdinalIgnoreCase));

            if (processModule is null)
            {
                return IntPtr.Zero;
            }

            // Calculate the address of the function

            var function = processModule.PeParser.Value.GetExportedFunctions().Find(exportedFunction => exportedFunction.Name != null && exportedFunction.Name.Equals(functionName, StringComparison.OrdinalIgnoreCase));

            var functionAddress = processModule.BaseAddress.AddOffset(function.Offset);

            // Get the export directory of the module

            var peHeaders = processModule.PeParser.Value.GetPeHeaders();

            var exportDirectory = IsWow64
                                ? peHeaders.NtHeaders32.OptionalHeader.DataDirectory[0]
                                : peHeaders.NtHeaders64.OptionalHeader.DataDirectory[0];

            // Calculate the start and end address of the export directory

            var exportDirectoryStartAddress = processModule.BaseAddress.AddOffset(exportDirectory.VirtualAddress);

            var exportDirectoryEndAddress = exportDirectoryStartAddress.AddOffset(exportDirectory.Size);

            // Determine if the function is forwarded to another function
            
            if ((ulong) functionAddress < (ulong) exportDirectoryStartAddress || (ulong) functionAddress > (ulong) exportDirectoryEndAddress)
            {
                return functionAddress;
            }
            
            // Read the forwarded function

            var forwardedFunctionBytes = new List<byte>();

            while (true)
            {
                var currentByte = _memoryManager.ReadVirtualMemory(functionAddress, 1);

                if (currentByte[0] == 0x00)
                {
                    break;
                }

                forwardedFunctionBytes.Add(currentByte[0]);

                functionAddress += 1;
            }

            var forwardedFunction = Encoding.Default.GetString(forwardedFunctionBytes.ToArray()).Split('.');

            // Get the name of the module the forwarded function resides in

            var forwardedFunctionModuleName = forwardedFunction[0] + ".dll";

            // Get the name of the forwarded function

            var forwardedFunctionName = forwardedFunction[1];

            return GetFunctionAddress(forwardedFunctionModuleName, forwardedFunctionName);

        }

        internal IntPtr GetFunctionAddress(string moduleName, ushort functionOrdinal)
        {
            // Look for the module in the module list of the remote process

            var processModule = Modules.Find(module => module.Name.Equals(moduleName, StringComparison.OrdinalIgnoreCase));

            if (processModule is null)
            {
                return IntPtr.Zero;
            }

            // Look for the function in the exported functions of the module

            var function = processModule.PeParser.Value.GetExportedFunctions().Find(exportedFunction => exportedFunction.Ordinal == functionOrdinal);

            return GetFunctionAddress(moduleName, function.Name);
        }

        internal Peb GetPeb()
        {
            if (IsWow64)
            {
                // Query the remote process for the address of the WOW64 PEB

                var pebAddressBuffer = Marshal.AllocHGlobal(sizeof(ulong));

                if (PInvoke.NtQueryInformationProcess(Process.SafeHandle, Enumerations.ProcessInformationClass.Wow64Information, pebAddressBuffer, sizeof(ulong), out _) != Enumerations.NtStatus.Success)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to query the remote process for the address of the WOW64 PEB");
                }

                var pebAddress = Marshal.PtrToStructure<ulong>(pebAddressBuffer);

                Marshal.FreeHGlobal(pebAddressBuffer);

                // Read the WOW64 PEB of the remote process

                var peb = _memoryManager.ReadVirtualMemory<Structures.Peb32>((IntPtr) pebAddress);

                return new Peb((IntPtr) peb.ApiSetMap, (IntPtr) peb.Ldr);
            }

            else
            {
                // Query the remote process for its basic information

                var basicInformationSize = Marshal.SizeOf<Structures.ProcessBasicInformation>();

                var basicInformationBuffer = Marshal.AllocHGlobal(basicInformationSize);

                if (PInvoke.NtQueryInformationProcess(Process.SafeHandle, Enumerations.ProcessInformationClass.BasicInformation, basicInformationBuffer, basicInformationSize, out _) != Enumerations.NtStatus.Success)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to query the remote process for its basic information");
                }

                var basicInformation = Marshal.PtrToStructure<Structures.ProcessBasicInformation>(basicInformationBuffer);

                Marshal.FreeHGlobal(basicInformationBuffer);

                // Read the PEB of the remote process

                var peb = _memoryManager.ReadVirtualMemory<Structures.Peb64>(basicInformation.PebBaseAddress);

                return new Peb((IntPtr) peb.ApiSetMap, (IntPtr) peb.Ldr);
            }
        }

        internal IEnumerable<Structures.LdrDataTableEntry64> GetPebEntries()
        {
            // Get the PEB of the remote process

            var peb = GetPeb();

            // Read the loader data of the PEB

            var pebLoaderData = _memoryManager.ReadVirtualMemory<Structures.PebLdrData64>(peb.Ldr);

            var currentPebEntryAddress = pebLoaderData.InLoadOrderModuleList.Flink;

            while (true)
            {
                // Read the current entry from the InLoadOrder linked list

                var pebEntry = _memoryManager.ReadVirtualMemory<Structures.LdrDataTableEntry64>((IntPtr) currentPebEntryAddress);

                yield return pebEntry;

                if (currentPebEntryAddress == pebLoaderData.InLoadOrderModuleList.Blink)
                {
                    break;
                }

                // Get the address of the next entry in the InLoadOrder linked list

                currentPebEntryAddress = pebEntry.InLoadOrderLinks.Flink;
            }
        }

        internal IEnumerable<Structures.LdrDataTableEntry32> GetWow64PebEntries()
        {
            // Get the WOW64 PEB of the remote process

            var peb = GetPeb();

            // Read the loader data of the WOW64 PEB

            var pebLoaderData = _memoryManager.ReadVirtualMemory<Structures.PebLdrData32>(peb.Ldr);

            var currentPebEntryAddress = pebLoaderData.InLoadOrderModuleList.Flink;

            while (true)
            {
                // Read the current entry from the InLoadOrder linked list

                var pebEntry = _memoryManager.ReadVirtualMemory<Structures.LdrDataTableEntry32>((IntPtr) currentPebEntryAddress);

                yield return pebEntry;

                if (currentPebEntryAddress == pebLoaderData.InLoadOrderModuleList.Blink)
                {
                    break;
                }

                // Get the address of the next entry in the InLoadOrder linked list

                currentPebEntryAddress = pebEntry.InLoadOrderLinks.Flink;
            }
        }

        internal void Refresh()
        {
            Modules.Clear();

            Modules.AddRange(GetProcessModules());

            Process.Refresh();
        }

        private void EnableDebuggerPrivileges()
        {
            try
            {
                Process.EnterDebugMode();
            }

            catch (Win32Exception)
            {
                // The local process isn't running in administrator mode
            }
        }

        private Process GetProcess(int processId)
        {
            try
            {
                return Process.GetProcessById(processId);
            }

            catch (ArgumentException)
            {
                throw new ArgumentException($"No process with the id {processId} is currently running");
            }
        }

        private Process GetProcess(string processName)
        {
            try
            {
                return Process.GetProcessesByName(processName)[0];
            }

            catch (IndexOutOfRangeException)
            {
                throw new ArgumentException($"No process with the name {processName} is currently running");
            }
        }

        private IEnumerable<Module> GetProcessModules()
        {
            if (IsWow64)
            {
                var filePathRegex = new Regex("System32", RegexOptions.IgnoreCase);

                foreach (var pebEntry in GetWow64PebEntries())
                {
                    // Read the file path of the entry

                    var entryFilePathBytes = _memoryManager.ReadVirtualMemory((IntPtr) pebEntry.FullDllName.Buffer, pebEntry.FullDllName.Length);

                    var entryFilePath = filePathRegex.Replace(Encoding.Unicode.GetString(entryFilePathBytes), "SysWOW64");

                    // Read the name of the entry

                    var entryNameBytes = _memoryManager.ReadVirtualMemory((IntPtr) pebEntry.BaseDllName.Buffer, pebEntry.BaseDllName.Length);

                    var entryName = Encoding.Unicode.GetString(entryNameBytes);

                    yield return new Module((IntPtr) pebEntry.DllBase, entryFilePath, entryName);
                }
            }

            else
            {
                foreach (var pebEntry in GetPebEntries())
                {
                    // Read the file path of the entry

                    var entryFilePathBytes = _memoryManager.ReadVirtualMemory((IntPtr) pebEntry.FullDllName.Buffer, pebEntry.FullDllName.Length);

                    var entryFilePath = Encoding.Unicode.GetString(entryFilePathBytes);

                    // Read the name of the entry

                    var entryNameBytes = _memoryManager.ReadVirtualMemory((IntPtr) pebEntry.BaseDllName.Buffer, pebEntry.BaseDllName.Length);

                    var entryName = Encoding.Unicode.GetString(entryNameBytes);

                    yield return new Module((IntPtr) pebEntry.DllBase, entryFilePath, entryName);
                }
            }
        }

        private bool IsProcessWow64()
        {
            if (!PInvoke.IsWow64Process(Process.SafeHandle, out var isWow64Process))
            {
                ExceptionHandler.ThrowWin32Exception("Failed to determine whether the remote process was running under WOW64");
            }

            return isWow64Process;
        }
    }
}