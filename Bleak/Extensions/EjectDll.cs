using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Bleak.Etc;
using Bleak.Services;

namespace Bleak.Extensions
{
    internal class EjectDll : IDisposable
    {   
        private readonly Properties _properties;
        
        internal EjectDll(Process process, string dllPath)
        {
            _properties = new Properties(process, dllPath);
        }
        
        public void Dispose()
        {
            _properties?.Dispose();
        }
        
        internal bool Eject()
        {   
            // Get the address of the LoadLibraryW method from kernel32.dll

            var freeLibraryAndExitThread = Tools.GetRemoteProcAddress(_properties, "kernel32.dll", "FreeLibraryAndExitThread");

            if (freeLibraryAndExitThread == IntPtr.Zero)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to find the address of the FreeLibraryAndExitThread method in kernel32.dll");
            }
            
            // Get the name of the dll
            
            var dllName = Path.GetFileName(_properties.DllPath);
            
            // Get an instance of the dll in the process

            var module = Tools.GetProcessModules(_properties.ProcessId).SingleOrDefault(m => string.Equals(m.Module, dllName, StringComparison.OrdinalIgnoreCase));
            
            if (module.Equals(default(Native.ModuleEntry)))
            {
                throw new ArgumentException($"There is no module named {dllName} loaded in the process");
            }
            
            // Get the base address of the dll
            
            var dllBaseAddress = module.BaseAddress;
            
            // Create a remote thread to call free library and exit thread in the process
            
            Native.RtlCreateUserThread(_properties.ProcessHandle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, freeLibraryAndExitThread, dllBaseAddress, out var remoteThreadHandle, 0);
            
            if (remoteThreadHandle is null)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to create a remote thread to call free library and exit thread in the process");
            }
            
            // Wait for the remote thread to finish its task
            
            Native.WaitForSingleObject(remoteThreadHandle, int.MaxValue);
            
            // Close the handle opened to the remote thread
            
            remoteThreadHandle?.Close();
            
            return true;
        }  
    }
}