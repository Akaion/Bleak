using Bleak.Memory;
using Bleak.PortableExecutable;
using Bleak.RemoteProcess;
using Bleak.Syscall;
using System;

namespace Bleak.Injection.Objects
{
    internal class InjectionProperties : IDisposable
    {
        internal readonly byte[] DllBytes;

        internal readonly string DllPath;

        internal readonly RemoteMemoryManager MemoryManager;

        internal readonly PeParser PeParser;

        internal readonly SyscallManager SyscallManager;

        internal readonly ProcessInstance RemoteProcess;

        internal InjectionProperties(int targetProcessId, byte[] dllBytes)
        {
            DllBytes = dllBytes;

            SyscallManager = new SyscallManager();

            RemoteProcess = new ProcessInstance(targetProcessId, SyscallManager);

            MemoryManager = new RemoteMemoryManager(RemoteProcess.Handle, SyscallManager);

            PeParser = new PeParser(DllBytes);
        }

        internal InjectionProperties(int targetProcessId, string dllPath)
        {
            DllPath = dllPath;

            SyscallManager = new SyscallManager();

            RemoteProcess = new ProcessInstance(targetProcessId, SyscallManager);

            MemoryManager = new RemoteMemoryManager(RemoteProcess.Handle, SyscallManager);

            PeParser = new PeParser(DllPath);
        }

        internal InjectionProperties(string targetProcessName, byte[] dllBytes)
        {
            DllBytes = dllBytes;

            SyscallManager = new SyscallManager();

            RemoteProcess = new ProcessInstance(targetProcessName, SyscallManager);

            MemoryManager = new RemoteMemoryManager(RemoteProcess.Handle, SyscallManager);

            PeParser = new PeParser(DllBytes);
        }

        internal InjectionProperties(string targetProcessName, string dllPath)
        {
            DllPath = dllPath;

            SyscallManager = new SyscallManager();

            RemoteProcess = new ProcessInstance(targetProcessName, SyscallManager);

            MemoryManager = new RemoteMemoryManager(RemoteProcess.Handle, SyscallManager);

            PeParser = new PeParser(dllPath);
        }

        public void Dispose()
        {
            PeParser.Dispose();

            SyscallManager.Dispose();

            RemoteProcess.Dispose();
        }
    }
}
