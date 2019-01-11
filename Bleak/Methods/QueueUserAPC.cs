using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Text;
using Bleak.Etc;
using Bleak.Services;
using Jupiter;

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

            if (Native.LoadLibrary("kernel32.dll") is null)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to load kernel32.dll into the process");
            }
            
            // Get the id of the process

            var processId = process.Id;
            
            // Get the address of the LoadLibraryW method from kernel32.dll
            
            var loadLibraryAddress = Native.GetProcAddress(Native.GetModuleHandle("kernel32.dll"), "LoadLibraryW");
            
            if (loadLibraryAddress == IntPtr.Zero)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to find the address of the LoadLibraryW method in kernel32.dll");
            }
            
            // Allocate memory for the dll path in the process
            
            var dllPathSize = dllPath.Length;

            var dllPathAddress = IntPtr.Zero;

            try
            {
                dllPathAddress = _memoryModule.AllocateMemory(processId, dllPathSize);
            }

            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to allocate memory for the dll path in the process");
            }
            
            // Write the dll path into the process
            
            var dllPathBytes = Encoding.Unicode.GetBytes(dllPath + "\0");

            try
            {
                _memoryModule.WriteMemory(processId, dllPathAddress, dllPathBytes);
            }

            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to write the dll path into the memory of the process");   
            }

            foreach (var thread in process.Threads.Cast<ProcessThread>())
            {
                // Open a handle to the thread

                var threadHandle = Native.OpenThread(Native.ThreadAccess.SetContext, false, thread.Id);

                if (threadHandle is null)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to open a handle to a thread in the process");
                }
                
                // Add a user-mode APC to the APC queue of the thread

                if (!Native.QueueUserAPC(loadLibraryAddress, threadHandle, dllPathAddress))
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to queue a user-mode apc to the apc queue of a thread in the process");
                }
                
                // Close the handle opened to the thread

                threadHandle?.Close();
            }
            
            // Free the memory previously allocated for the dll path

            try
            {
                _memoryModule.FreeMemory(processId, dllPathAddress);
            }

            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to free the memory allocated for the dll path in the process");   
            }

            return true;
        }
    }
}