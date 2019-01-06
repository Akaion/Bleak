using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using static Bleak.Etc.Native;

namespace Bleak.Extensions
{
    internal class EjectDll
    {
        internal bool Eject(Process process, string dllPath)
        {
            // Ensure the process has kernel32.dll loaded

            if (LoadLibrary("kernel32.dll") is null)
            {
                return false;
            }
            
            // Get the address of the FreeLibrary method in kernel32.dll
            
            var freeLibraryAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "FreeLibrary");

            if (freeLibraryAddress == IntPtr.Zero)
            {
                return false;
            }
            
            // Get the name of the dll

            var dllName = Path.GetFileName(dllPath);
            
            // Get an instance of the dll in the process
            
            var module = process.Modules.Cast<ProcessModule>().SingleOrDefault(m => string.Equals(m.ModuleName, dllName, StringComparison.OrdinalIgnoreCase));

            if (module is null)
            {
                return false;
            }
            
            // Get the base address of the dll

            var dllBaseAddress = module.BaseAddress;

            if (dllBaseAddress == IntPtr.Zero)
            {
                return false;
            }
            
            // Open a handle to the process

            var processHandle = process.SafeHandle;
            
            // Create a remote thread to call free library in the process
            
            RtlCreateUserThread(processHandle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, freeLibraryAddress, dllBaseAddress, out var remoteThreadHandle, 0);

            if (remoteThreadHandle is null)
            {
                return false;
            }
            
            // Wait for the remote thread to finish its task
            
            WaitForSingleObject(remoteThreadHandle, int.MaxValue);
            
            // Close the handle opened to the process
            
            processHandle.Close();
            
            return true;
        }
    }
}