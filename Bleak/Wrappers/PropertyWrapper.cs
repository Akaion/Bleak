using Bleak.Handlers;
using Bleak.Native;
using Bleak.PortableExecutable;
using Bleak.Syscall;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Bleak.Wrappers
{
    internal class PropertyWrapper : IDisposable
    {
        internal readonly byte[] DllBytes;

        internal readonly string DllPath;

        internal readonly Lazy<bool> IsWow64Process;

        internal readonly Lazy<MemoryWrapper> MemoryManager;

        internal readonly Dictionary<string, Tools.Objects.PeInstance> PeInstances;

        internal readonly PortableExecutableParser PeParser;

        internal readonly Process Process;

        internal readonly Lazy<SafeProcessHandle> ProcessHandle;

        internal readonly SyscallManager SyscallManager;

        internal PropertyWrapper(Process process, byte[] dllBytes)
        {
            DllBytes = dllBytes;

            IsWow64Process = new Lazy<bool>(GetProcessArchitecture);

            MemoryManager = new Lazy<MemoryWrapper>(() => new MemoryWrapper(ProcessHandle.Value));

            PeInstances = new Dictionary<string, Tools.Objects.PeInstance>();

            PeParser = new PortableExecutableParser(dllBytes);

            Process = process;

            ProcessHandle = new Lazy<SafeProcessHandle>(OpenProcessHandle);

            SyscallManager = new SyscallManager();
        }

        internal PropertyWrapper(Process process, string dllPath)
        {
            DllPath = dllPath;

            IsWow64Process = new Lazy<bool>(GetProcessArchitecture);

            MemoryManager = new Lazy<MemoryWrapper>(() => new MemoryWrapper(ProcessHandle.Value));

            PeInstances = new Dictionary<string, Tools.Objects.PeInstance>();

            PeParser = new PortableExecutableParser(dllPath);

            Process = process;

            ProcessHandle = new Lazy<SafeProcessHandle>(OpenProcessHandle);

            SyscallManager = new SyscallManager();
        }
        
        public void Dispose()
        {
            MemoryManager.Value.Dispose();

            foreach (var peInstance in PeInstances.Values)
            {
                peInstance.Dispose();
            }

            Process.Dispose();

            ProcessHandle.Value.Dispose();

            SyscallManager.Dispose();
        }

        private bool GetProcessArchitecture()
        {
            if (!PInvoke.IsWow64Process(ProcessHandle.Value, out var isWow64Process))
            {
                ExceptionHandler.ThrowWin32Exception("Failed to determine whether the target process was running under Wow64");
            }

            return isWow64Process;
        }

        private SafeProcessHandle OpenProcessHandle()
        {
            return (SafeProcessHandle) SyscallManager.InvokeSyscall<Syscall.Definitions.NtOpenProcess>(Process.Id);
        }
    }
}
