using System;
using System.Diagnostics;
using System.Linq;
using System.Text;
using Jupiter;
using static Bleak.Etc.Native;

namespace Bleak.Methods
{
    internal class QueueUserApc
    {
        private readonly MemoryModule _memoryModule;
        
        internal QueueUserApc()
        {
            _memoryModule = new MemoryModule();
        }
        
        internal bool Inject(Process process, string dllPath)
        {
            // Ensure the process has kernel32.dll loaded

            if (LoadLibrary("kernel32.dll") is null)
            {
                return false;
            }
            
            // Get the id of the process

            var processId = process.Id;
            
            // Get the address of the LoadLibraryW method from kernel32.dll
            
            var loadLibraryAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryW");
            
            if (loadLibraryAddress == IntPtr.Zero)
            {
                return false;
            }
            
            // Allocate memory for the dll path in the process
            
            var dllPathSize = dllPath.Length;

            var dllPathAddress = _memoryModule.AllocateMemory(processId, dllPathSize);

            if (dllPathAddress == IntPtr.Zero)
            {
                return false;
            }
            
            // Write the dll path into the process
            
            var dllPathBytes = Encoding.Unicode.GetBytes(dllPath + "\0");

            if (!_memoryModule.WriteMemory(processId, dllPathAddress, dllPathBytes))
            {
                return false;
            }

            foreach (var thread in process.Threads.Cast<ProcessThread>())
            {
                // Open a handle to the thread

                var threadHandle = OpenThread(ThreadAccess.SetContext, false, thread.Id);

                if (threadHandle is null)
                {
                    return false;
                }
                
                // Adda user-mode APC to the APC queue of the thread

                if (!QueueUserAPC(loadLibraryAddress, threadHandle, dllPathAddress))
                {
                    return false;
                }
                
                // Close the handle opened to the thread

                threadHandle.Close();
            }
            
            return true;
        }
    }
}