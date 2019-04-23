using Bleak.Handlers;
using Bleak.Memory;
using Bleak.Native;
using Bleak.RemoteProcess.Objects;
using Bleak.Syscall;
using Bleak.Syscall.Definitions;
using Bleak.Tools;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace Bleak.RemoteProcess
{
    internal class ProcessInstance : IDisposable
    {
        internal readonly SafeProcessHandle Handle;

        internal readonly bool IsWow64;

        internal readonly List<ModuleInstance> Modules;

        private readonly RemoteMemoryManager _memoryManager;

        private readonly Dictionary<string, PeInstance> _peInstanceCache;

        internal readonly Process TargetProcess;

        private readonly SyscallManager _syscallManager;

        internal ProcessInstance(int targetProcessId, SyscallManager syscallManager)
        {
            Modules = new List<ModuleInstance>();

            _peInstanceCache = new Dictionary<string, PeInstance>();

            TargetProcess = GetTargetProcess(targetProcessId);

            _syscallManager = syscallManager;

            Handle = OpenProcessHandle();

            IsWow64 = GetProcessArchitecture();

            _memoryManager = new RemoteMemoryManager(Handle, _syscallManager);

            EnableDebuggerPrivileges();

            Modules.AddRange(GetProcessModules());
        }

        internal ProcessInstance(string targetProcessName, SyscallManager syscallManager)
        {
            Modules = new List<ModuleInstance>();

            _peInstanceCache = new Dictionary<string, PeInstance>();

            TargetProcess = GetTargetProcess(targetProcessName);

            _syscallManager = syscallManager;

            Handle = OpenProcessHandle();

            IsWow64 = GetProcessArchitecture();

            _memoryManager = new RemoteMemoryManager(Handle, _syscallManager);

            EnableDebuggerPrivileges();

            Modules.AddRange(GetProcessModules());
        }

        public void Dispose()
        {
            foreach (var peInstance in _peInstanceCache.Values)
            {
                peInstance.Dispose();
            }

            TargetProcess.Dispose();

            Handle.Dispose();
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

        internal IntPtr GetFunctionAddress(string moduleName, string functionName)
        {
            // Look for the module in the module list of the process

            var processModule = Modules.Find(module => module.Name.Equals(moduleName, StringComparison.OrdinalIgnoreCase));

            if (processModule is null)
            {
                return IntPtr.Zero;
            }

            if (!_peInstanceCache.ContainsKey(moduleName))
            {
                _peInstanceCache.Add(moduleName, new PeInstance(processModule.FilePath));
            }

            var peInstance = _peInstanceCache[moduleName];

            // Calculate the address of the function

            var functionOffset = peInstance.ExportedFunctions.Find(function => function.Name != null && function.Name.Equals(functionName, StringComparison.OrdinalIgnoreCase)).Offset;

            var functionAddress = processModule.BaseAddress.AddOffset(functionOffset);

            // Get the export directory of the module

            var peHeaders = peInstance.PeParser.GetHeaders();

            var exportDirectory = IsWow64 
                                ? peHeaders.NtHeaders32.OptionalHeader.DataDirectory[0]
                                : peHeaders.NtHeaders64.OptionalHeader.DataDirectory[0];

            // Calculate the start and end address of the export directory

            var exportTableStartAddress = processModule.BaseAddress.AddOffset(exportDirectory.VirtualAddress);

            var exportTableEndAddress = exportTableStartAddress.AddOffset(exportDirectory.Size);

            // Check whether the function is forwarded to another function

            if ((ulong) functionAddress >= (ulong) exportTableStartAddress && (ulong) functionAddress <= (ulong) exportTableEndAddress)
            {
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

                var forwardedFunctionModuleName = string.Concat(forwardedFunction[0], ".dll");
                
                // Get the name of the forwarded function

                var forwardedFunctionName = forwardedFunction[1];

                return GetFunctionAddress(forwardedFunctionModuleName, forwardedFunctionName);
            }

            return functionAddress;
        }

        internal IEnumerable<Structures.LdrDataTableEntry64> GetPebEntries()
        {
            // Query the target process for the ProcessBasicInformation of the process

            var processBasicInformationBuffer = (IntPtr) _syscallManager.InvokeSyscall<NtQueryInformationProcess>(Handle, Enumerations.ProcessInformationClass.BasicInformation);

            var processBasicInformation = Marshal.PtrToStructure<Structures.ProcessBasicInformation>(processBasicInformationBuffer);

            // Read the PEB of the target process

            var peb = _memoryManager.ReadVirtualMemory<Structures.Peb64>(processBasicInformation.PebBaseAddress);

            // Read the loader data of the PEB

            var pebLoaderData = _memoryManager.ReadVirtualMemory<Structures.PebLdrData64>((IntPtr) peb.Ldr);

            var currentPebEntry = pebLoaderData.InLoadOrderModuleList.Flink;

            while (true)
            {
                if (currentPebEntry == pebLoaderData.InLoadOrderModuleList.Blink)
                {
                    // Read the last entry from the InLoadOrder doubly linked list

                    yield return _memoryManager.ReadVirtualMemory<Structures.LdrDataTableEntry64>((IntPtr) currentPebEntry);

                    break;
                }

                // Read the current entry from the InLoadOrder doubly linked list

                var pebEntry = _memoryManager.ReadVirtualMemory<Structures.LdrDataTableEntry64>((IntPtr) currentPebEntry);

                yield return pebEntry;
                
                // Get the address of the next entry in the InLoadOrder doubly linked list

                currentPebEntry = pebEntry.InLoadOrderLinks.Flink;
            }
        }

        private bool GetProcessArchitecture()
        {
            if (!PInvoke.IsWow64Process(Handle, out var isWow64Process))
            {
                ExceptionHandler.ThrowWin32Exception("Failed to determine whether the target process was running under WOW64");
            }

            return isWow64Process;
        }

        private IEnumerable<ModuleInstance> GetProcessModules()
        {
            if (IsWow64)
            {
                var entryFilePathRegex = new Regex("System32", RegexOptions.IgnoreCase);

                foreach (var pebEntry in GetWow64PebEntries())
                {
                    // Read the file path of the entry

                    var entryFilePathBytes = _memoryManager.ReadVirtualMemory((IntPtr) pebEntry.FullDllName.Buffer, pebEntry.FullDllName.Length);

                    var entryFilePath = entryFilePathRegex.Replace(Encoding.Unicode.GetString(entryFilePathBytes), "SysWOW64");

                    // Read the name of the entry

                    var entryNameBytes = _memoryManager.ReadVirtualMemory((IntPtr) pebEntry.BaseDllName.Buffer, pebEntry.BaseDllName.Length);

                    var entryName = Encoding.Unicode.GetString(entryNameBytes);

                    yield return new ModuleInstance((IntPtr) pebEntry.DllBase, entryFilePath, entryName);
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

                    yield return new ModuleInstance((IntPtr)pebEntry.DllBase, entryFilePath, entryName);
                }
            }
        }

        private Process GetTargetProcess(int targetProcessId)
        {
            try
            {
                return Process.GetProcessById(targetProcessId);
            }

            catch (ArgumentException)
            {
                throw new ArgumentException($"No process with the id {targetProcessId} is currently running");
            }
        }

        private Process GetTargetProcess(string targetProcessName)
        {
            try
            {
                return Process.GetProcessesByName(targetProcessName)[0];
            }

            catch (IndexOutOfRangeException)
            {
                throw new ArgumentException($"No process with the name {targetProcessName} is currently running");
            }
        }

        internal IEnumerable<Structures.LdrDataTableEntry32> GetWow64PebEntries()
        {
            // Query the target process for the base address of the WOW64 PEB

            var pebBaseAddressBuffer = (IntPtr)_syscallManager.InvokeSyscall<NtQueryInformationProcess>(Handle, Enumerations.ProcessInformationClass.Wow64Information);

            var pebBaseAddress = Marshal.PtrToStructure<ulong>(pebBaseAddressBuffer);

            // Read the WOW64 PEB of the target process

            var peb = _memoryManager.ReadVirtualMemory<Structures.Peb32>((IntPtr)pebBaseAddress);

            // Read the loader data of the WOW64 PEB

            var pebLoaderData = _memoryManager.ReadVirtualMemory<Structures.PebLdrData32>((IntPtr)peb.Ldr);

            var currentPebEntry = pebLoaderData.InLoadOrderModuleList.Flink;

            while (true)
            {
                if (currentPebEntry == pebLoaderData.InLoadOrderModuleList.Blink)
                {
                    // Read the last entry from the InLoadOrder doubly linked list

                    yield return _memoryManager.ReadVirtualMemory<Structures.LdrDataTableEntry32>((IntPtr) currentPebEntry);

                    break;
                }

                // Read the current entry from the InLoadOrder doubly linked list

                var pebEntry = _memoryManager.ReadVirtualMemory<Structures.LdrDataTableEntry32>((IntPtr) currentPebEntry);

                yield return pebEntry;

                // Get the address of the next entry in the InLoadOrder doubly linked list

                currentPebEntry = pebEntry.InLoadOrderLinks.Flink;
            }
        }

        private SafeProcessHandle OpenProcessHandle()
        {
            return (SafeProcessHandle) _syscallManager.InvokeSyscall<NtOpenProcess>(TargetProcess.Id);
        }

        internal void Refresh()
        {
            Modules.Clear();

            Modules.AddRange(GetProcessModules());

            TargetProcess.Refresh();
        }
    }
}
