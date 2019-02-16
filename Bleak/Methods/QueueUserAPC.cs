using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Text;
using Bleak.Etc;
using Bleak.Services;

namespace Bleak.Methods
{
    internal class QueueUserApc : IDisposable
    {
        private readonly ProcessThreadCollection _processThreads;
        
        private readonly Properties _properties;
        
        internal QueueUserApc(Process process, string dllPath)
        {
            _processThreads = process.Threads;
            
            _properties = new Properties(process, dllPath);
        }
        
        public void Dispose()
        {
            _properties?.Dispose();
        }
        
        internal bool Inject()
        {   
            // Get the address of the LoadLibraryW method from kernel32.dll

            var loadLibraryAddress = Tools.GetRemoteProcAddress(_properties, "kernel32.dll", "LoadLibraryW");

            if (loadLibraryAddress == IntPtr.Zero)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to find the address of the LoadLibraryW method in kernel32.dll");
            }
            
            // Allocate memory for the dll path in the remote process
            
            var dllPathAddress = IntPtr.Zero;

            try
            {
                dllPathAddress = _properties.MemoryModule.AllocateMemory(_properties.ProcessId, _properties.DllPath.Length);
            }

            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to allocate memory for the dll path in the remote process");
            }
            
            // Write the dll path into the memory of the remote process
            
            var dllPathBytes = Encoding.Unicode.GetBytes(_properties.DllPath + "\0");

            try
            {
                _properties.MemoryModule.WriteMemory(_properties.ProcessId, dllPathAddress, dllPathBytes);
            }

            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to write the dll path into the memory of the remote process");   
            }
            
            foreach (var thread in _processThreads.Cast<ProcessThread>())
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
                    ExceptionHandler.ThrowWin32Exception("Failed to queue a user-mode apc to the apc queue of a thread in the remote process");
                }
                
                threadHandle?.Close();
            }
            
            // Free the memory previously allocated for the dll path in the remote process

            try
            {
                _properties.MemoryModule.FreeMemory(_properties.ProcessId, dllPathAddress);
            }

            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to free the memory allocated for the dll path in the remote process");   
            }

            return true;
        }
    }
}