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
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace Bleak.RemoteProcess
{
    internal class ProcessInstance : IDisposable
    {
        internal readonly bool IsWow64;

        private readonly MemoryManager _memoryManager;

        private readonly Dictionary<string, PeInstance> _peInstances;

        internal readonly Process Process;

        internal readonly SafeProcessHandle Handle;

        internal readonly List<ModuleInstance> Modules;

        private readonly SyscallManager _syscallManager;

        internal ProcessInstance(int targetProcessId, SyscallManager syscallManager)
        {
            Process = GetTargetProcess(targetProcessId);

            _syscallManager = syscallManager;

            Handle = OpenProcessHandle();

            IsWow64 = GetProcessArchitecture();

            _memoryManager = new MemoryManager(Handle, _syscallManager);

            _peInstances = new Dictionary<string, PeInstance>();

            Modules = new List<ModuleInstance>();

            GetProcessModules();
        }

        internal ProcessInstance(string targetProcessName, SyscallManager syscallManager)
        {
            Process = GetTargetProcess(targetProcessName);

            _syscallManager = syscallManager;

            Handle = OpenProcessHandle();

            IsWow64 = GetProcessArchitecture();

            _memoryManager = new MemoryManager(Handle, _syscallManager);

            _peInstances = new Dictionary<string, PeInstance>();

            Modules = new List<ModuleInstance>();

            GetProcessModules();
        }

        public void Dispose()
        {
            foreach (var peInstance in _peInstances)
            {
                peInstance.Value.Dispose();
            }

            Process.Dispose();

            Handle.Dispose();
        }

        internal IntPtr GetFunctionAddress(string moduleName, string functionName)
        {
            // Look for the module in the process module list

            var processModule = Modules.Find(module => module.Name.Equals(moduleName, StringComparison.OrdinalIgnoreCase));

            if (processModule is null)
            {
                return IntPtr.Zero;
            }

            if (!_peInstances.TryGetValue(moduleName, out var peInstance))
            {
                peInstance = new PeInstance(processModule.FilePath);

                _peInstances.Add(moduleName, peInstance);
            }

            // Calculate the address of the the function

            var functionAddress = processModule.BaseAddress + (int) peInstance.ExportedFunctions.Find(function => function.Name != null && function.Name.Equals(functionName, StringComparison.OrdinalIgnoreCase)).Offset;

            var peHeaders = peInstance.PeParser.GetHeaders();

            // Calculate the start and end address of the modules export table

            var exportDirectory = IsWow64 ? peHeaders.NtHeaders32.OptionalHeader.DataDirectory[0] : peHeaders.NtHeaders64.OptionalHeader.DataDirectory[0];

            var exportTableStartAddress = (ulong) processModule.BaseAddress + exportDirectory.VirtualAddress;

            var exportTableEndAddress = exportTableStartAddress + exportDirectory.Size;

            // Check whether the function is forwarded to another function

            if ((ulong) functionAddress >= exportTableStartAddress && (ulong) functionAddress <= exportTableEndAddress)
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

                var forwardedFunctionModuleName = forwardedFunction[0] + ".dll";

                // Get the name of the forwarded function

                var forwardedFunctionName = forwardedFunction[1];

                return GetFunctionAddress(forwardedFunctionModuleName, forwardedFunctionName);
            }

            return functionAddress;
        }

        internal List<Structures.LdrDataTableEntry64> GetPebEntries()
        {
            var pebEntries = new List<Structures.LdrDataTableEntry64>();

            // Query the target process for the ProcessBasicInformation

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
                    break;
                }

                // Read the current entry from the InLoadOrder doubly linked list

                var pebEntry = _memoryManager.ReadVirtualMemory<Structures.LdrDataTableEntry64>((IntPtr) currentPebEntry);

                pebEntries.Add(pebEntry);

                // Get the address of the next entry in the InLoadOrder doubly linked list

                currentPebEntry = pebEntry.InLoadOrderLinks.Flink;
            }

            MemoryTools.FreeMemoryForBuffer(processBasicInformationBuffer);

            return pebEntries;
        }

        private Process GetTargetProcess(int targetProcessId)
        {
            Process process;

            try
            {
                process = Process.GetProcessById(targetProcessId);
            }

            catch (ArgumentException)
            {
                throw new ArgumentException($"No process with the id {targetProcessId} is currently running");
            }

            return process;
        }

        private Process GetTargetProcess(string targetProcessName)
        {
            Process process;

            try
            {
                process = Process.GetProcessesByName(targetProcessName)[0];
            }

            catch (IndexOutOfRangeException)
            {
                throw new ArgumentException($"No process with the name {targetProcessName} is currently running");
            }

            return process;
        }

        private bool GetProcessArchitecture()
        {
            if (!PInvoke.IsWow64Process(Handle, out var isWow64Process))
            {
                ExceptionHandler.ThrowWin32Exception("Failed to determine whether the target process was running under WOW64");
            }

            return isWow64Process;
        }

        private void GetProcessModules()
        {
            Modules.Clear();

            if (IsWow64)
            {
                var moduleFilePathRegex = new Regex("System32", RegexOptions.IgnoreCase);

                foreach (var pebEntry in GetWow64PebEntries())
                {
                    // Read the file path of the module

                    var moduleFilePathBytes = _memoryManager.ReadVirtualMemory((IntPtr) pebEntry.FullDllName.Buffer, pebEntry.FullDllName.Length);

                    var moduleFilePath = moduleFilePathRegex.Replace(Encoding.Default.GetString(moduleFilePathBytes).Replace("\0", ""), "SysWOW64");

                    // Read the name of the module

                    var moduleNameBytes = _memoryManager.ReadVirtualMemory((IntPtr) pebEntry.BaseDllName.Buffer, pebEntry.BaseDllName.Length);

                    var moduleName = Encoding.Default.GetString(moduleNameBytes).Replace("\0", "");

                    Modules.Add(new ModuleInstance((IntPtr) pebEntry.DllBase, moduleFilePath, moduleName));
                }
            }

            else
            {
                foreach (var pebEntry in GetPebEntries())
                {
                    // Read the file path of the module

                    var moduleFilePathBytes = _memoryManager.ReadVirtualMemory((IntPtr) pebEntry.FullDllName.Buffer, pebEntry.FullDllName.Length);

                    var moduleFilePath = Encoding.Default.GetString(moduleFilePathBytes).Replace("\0", "");

                    // Read the name of the module

                    var moduleNameBytes = _memoryManager.ReadVirtualMemory((IntPtr) pebEntry.BaseDllName.Buffer, pebEntry.BaseDllName.Length);

                    var moduleName = Encoding.Default.GetString(moduleNameBytes).Replace("\0", "");

                    Modules.Add(new ModuleInstance((IntPtr) pebEntry.DllBase, moduleFilePath, moduleName));
                }
            }
        }

        internal List<Structures.LdrDataTableEntry32> GetWow64PebEntries()
        {
            var pebEntries = new List<Structures.LdrDataTableEntry32>();

            // Query the target process for the base address of the WOW64 PEB

            var pebBaseAddressBuffer = (IntPtr) _syscallManager.InvokeSyscall<NtQueryInformationProcess>(Handle, Enumerations.ProcessInformationClass.Wow64Information);

            var pebBaseAddress = Marshal.PtrToStructure<ulong>(pebBaseAddressBuffer);

            // Read the WOW64 PEB of the target process

            var peb = _memoryManager.ReadVirtualMemory<Structures.Peb32>((IntPtr) pebBaseAddress);

            // Read the loader data of the WOW64 PEB

            var pebLoaderData = _memoryManager.ReadVirtualMemory<Structures.PebLdrData32>((IntPtr) peb.Ldr);

            var currentPebEntry = pebLoaderData.InLoadOrderModuleList.Flink;

            while (true)
            {
                if (currentPebEntry == pebLoaderData.InLoadOrderModuleList.Blink)
                {
                    break;
                }

                // Read the current entry from the InLoadOrder doubly linked list

                var pebEntry = _memoryManager.ReadVirtualMemory<Structures.LdrDataTableEntry32>((IntPtr) currentPebEntry);

                pebEntries.Add(pebEntry);

                // Get the address of the next entry in the InLoadOrder doubly linked list

                currentPebEntry = pebEntry.InLoadOrderLinks.Flink;
            }

            MemoryTools.FreeMemoryForBuffer(pebBaseAddressBuffer);

            return pebEntries;
        }

        private SafeProcessHandle OpenProcessHandle()
        {
            return (SafeProcessHandle) _syscallManager.InvokeSyscall<NtOpenProcess>(Process.Id);
        }

        internal void Refresh()
        {
            Process.Refresh();

            GetProcessModules();
        }
    }
}
