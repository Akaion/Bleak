using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Bleak.Etc;
using Bleak.Services;

namespace Bleak.Extensions
{
    internal class EjectDll
    {
        internal bool Eject(Process process, string dllPath)
        {
            // Ensure the process has kernel32.dll loaded

            if (Native.LoadLibrary("kernel32.dll") is null)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to load kernel32.dll into the process");
            }
            
            // Get the address of the FreeLibraryAndExitThread method in kernel32.dll
            
            var freeLibraryAddress = Native.GetProcAddress(Native.GetModuleHandle("kernel32.dll"), "FreeLibraryAndExitThread");

            if (freeLibraryAddress == IntPtr.Zero)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to find the address of the FreeLibrary method in kernel32.dll");
            }
            
            // Get the name of the dll

            var dllName = Path.GetFileName(dllPath);
            
            // Get an instance of the dll in the process
            
            var module = process.Modules.Cast<ProcessModule>().SingleOrDefault(m => string.Equals(m.ModuleName, dllName, StringComparison.OrdinalIgnoreCase));

            if (module is null)
            {
                throw new ArgumentException($"There is no module named {dllName} loaded in the process");
            }
            
            // Get the base address of the dll

            var dllBaseAddress = module.BaseAddress;

            // Open a handle to the process

            var processHandle = process.SafeHandle;
            
            // Create a remote thread to call free library and exit thread in the process
            
            Native.RtlCreateUserThread(processHandle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, freeLibraryAddress, dllBaseAddress, out var remoteThreadHandle, 0);

            if (remoteThreadHandle is null)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to create a remote thread to call free library in the process");
            }
            
            // Wait for the remote thread to finish its task
            
            Native.WaitForSingleObject(remoteThreadHandle, int.MaxValue);
            
            // Close the handle opened to the process
            
            processHandle?.Close();
            
            // Close the handle opened to the remote thread
            
            remoteThreadHandle?.Close();
            
            return true;
        }
    }
}