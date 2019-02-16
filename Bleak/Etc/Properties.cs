using System;
using System.Diagnostics;
using Jupiter;
using Microsoft.Win32.SafeHandles;
using PeNet;

namespace Bleak.Etc
{
    internal class Properties : IDisposable
    {
        internal readonly string DllPath;
        
        internal readonly bool IsWow64;
        
        internal readonly MemoryModule MemoryModule;
        
        internal readonly PeFile PeHeaders;
        
        internal readonly int ProcessId;
        
        internal readonly SafeProcessHandle ProcessHandle;
        
        internal Properties(Process process, string dllPath)
        {
            DllPath = dllPath;
            
            // Determine if the process is running under Wow64
            
            Native.IsWow64Process(process.SafeHandle, out IsWow64);
            
            MemoryModule = new MemoryModule();

            // Get the pe headers of the dll
            
            PeHeaders = new PeFile(dllPath);

            ProcessId = process.Id;

            // Open a handle to the process
            
            ProcessHandle = process.SafeHandle;
        }
        
        public void Dispose()
        {
            // Close the handle opened to the process
            
            ProcessHandle?.Close();
        }
    }
}