using Bleak.Memory;
using Bleak.PortableExecutable;
using Bleak.RemoteProcess;
using Bleak.Syscall;
using System;

namespace Bleak.Wrappers
{
    internal class PropertyWrapper : IDisposable
    {
        internal readonly byte[] DllBytes;

        internal readonly string DllPath;

        internal readonly MemoryManager MemoryManager;

        internal readonly PortableExecutableParser PeParser;

        internal readonly SyscallManager SyscallManager;

        internal readonly ProcessInstance TargetProcess;

        internal PropertyWrapper(int targetProcessId, byte[] dllBytes)
        {
            DllBytes = dllBytes;

            SyscallManager = new SyscallManager();

            TargetProcess = new ProcessInstance(targetProcessId, SyscallManager);

            MemoryManager = new MemoryManager(TargetProcess.Handle, SyscallManager);

            PeParser = new PortableExecutableParser(DllBytes);
        }

        internal PropertyWrapper(int targetProcessId, string dllPath)
        {
            DllPath = dllPath;

            SyscallManager = new SyscallManager();

            TargetProcess = new ProcessInstance(targetProcessId, SyscallManager);

            MemoryManager = new MemoryManager(TargetProcess.Handle, SyscallManager);

            PeParser = new PortableExecutableParser(DllPath);
        }

        internal PropertyWrapper(string targetProcessName, byte[] dllBytes)
        {
            DllBytes = dllBytes;

            SyscallManager = new SyscallManager();

            TargetProcess = new ProcessInstance(targetProcessName, SyscallManager);

            MemoryManager = new MemoryManager(TargetProcess.Handle, SyscallManager);

            PeParser = new PortableExecutableParser(DllBytes);
        }

        internal PropertyWrapper(string targetProcessName, string dllPath)
        {
            DllPath = dllPath;

            SyscallManager = new SyscallManager();

            TargetProcess = new ProcessInstance(targetProcessName, SyscallManager);

            MemoryManager = new MemoryManager(TargetProcess.Handle, SyscallManager);

            PeParser = new PortableExecutableParser(DllPath);
        }

        public void Dispose()
        {
            PeParser.Dispose();

            SyscallManager.Dispose();

            TargetProcess.Dispose();
        }
    }
}
