using System;
using System.IO;
using Bleak.Assembly;
using Bleak.Memory;
using Bleak.PortableExecutable;
using Bleak.ProgramDatabase;
using Bleak.RemoteProcess;

namespace Bleak.Injection.Objects
{
    internal class InjectionWrapper : IDisposable
    {
        internal readonly Assembler Assembler;

        internal readonly byte[] DllBytes;

        internal readonly string DllPath;

        internal readonly InjectionMethod InjectionMethod;

        internal readonly MemoryManager MemoryManager;

        internal readonly Lazy<PdbParser> PdbParser;
        
        internal readonly PeParser PeParser;

        internal readonly ProcessWrapper RemoteProcess;

        internal InjectionWrapper(InjectionMethod injectionMethod, int processId, byte[] dllBytes)
        {
            RemoteProcess = new ProcessWrapper(processId);

            Assembler = new Assembler(RemoteProcess.IsWow64);

            DllBytes = dllBytes;

            InjectionMethod = injectionMethod;

            MemoryManager = new MemoryManager(RemoteProcess.Process.SafeHandle);

            PdbParser = new Lazy<PdbParser>(() => new PdbParser(RemoteProcess.Modules.Find(module => module.Name == "ntdll.dll")));
            
            PeParser = new PeParser(dllBytes);
        }

        internal InjectionWrapper(InjectionMethod injectionMethod, int processId, string dllPath)
        {
            RemoteProcess = new ProcessWrapper(processId);

            Assembler = new Assembler(RemoteProcess.IsWow64);

            DllBytes = File.ReadAllBytes(dllPath);

            DllPath = dllPath;

            InjectionMethod = injectionMethod;

            MemoryManager = new MemoryManager(RemoteProcess.Process.SafeHandle);

            PdbParser = new Lazy<PdbParser>(() => new PdbParser(RemoteProcess.Modules.Find(module => module.Name == "ntdll.dll")));
            
            PeParser = new PeParser(dllPath);
        }

        internal InjectionWrapper(InjectionMethod injectionMethod, string processName, byte[] dllBytes)
        {
            RemoteProcess = new ProcessWrapper(processName);

            Assembler = new Assembler(RemoteProcess.IsWow64);

            DllBytes = dllBytes;

            InjectionMethod = injectionMethod;

            MemoryManager = new MemoryManager(RemoteProcess.Process.SafeHandle);

            PdbParser = new Lazy<PdbParser>(() => new PdbParser(RemoteProcess.Modules.Find(module => module.Name == "ntdll.dll")));
            
            PeParser = new PeParser(dllBytes);
        }

        internal InjectionWrapper(InjectionMethod injectionMethod, string processName, string dllPath)
        {
            RemoteProcess = new ProcessWrapper(processName);

            Assembler = new Assembler(RemoteProcess.IsWow64);

            DllBytes = File.ReadAllBytes(dllPath);

            DllPath = dllPath;

            InjectionMethod = injectionMethod;

            MemoryManager = new MemoryManager(RemoteProcess.Process.SafeHandle);

            PdbParser = new Lazy<PdbParser>(() => new PdbParser(RemoteProcess.Modules.Find(module => module.Name == "ntdll.dll")));
            
            PeParser = new PeParser(dllPath);
        }

        public void Dispose()
        {
            PeParser.Dispose();

            RemoteProcess.Dispose();
        }
    }
}