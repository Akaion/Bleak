using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using Bleak.Etc;
using Bleak.Services;

namespace Bleak.Methods
{
    internal class ZwCreateThreadEx : IDisposable
    {
        private readonly Properties _properties;

        internal ZwCreateThreadEx(Process process, string dllPath)
        {
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
            
            // Write the dll path into the remote process
            
            var dllPathBytes = Encoding.Unicode.GetBytes(_properties.DllPath + "\0");

            try
            {
                _properties.MemoryModule.WriteMemory(_properties.ProcessId, dllPathAddress, dllPathBytes);
            }

            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to write the dll path into the memory of the remote process");   
            }
            
            // Create a remote thread to call load library in the process
            
            Native.ZwCreateThreadEx(out var remoteThreadHandle, Native.AccessMask.SpecificRightsAll | Native.AccessMask.StandardRightsAll, IntPtr.Zero, _properties.ProcessHandle, loadLibraryAddress, dllPathAddress, Native.CreationFlags.HideFromDebugger, 0, 0, 0, IntPtr.Zero);
            
            if (remoteThreadHandle is null)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to create a remote thread to call load library in the process");
            }
            
            // Wait for the remote thread to finish its task
            
            Native.WaitForSingleObject(remoteThreadHandle, int.MaxValue);
            
            // Free the memory previously allocated for the dll path

            try
            {
                _properties.MemoryModule.FreeMemory(_properties.ProcessId, dllPathAddress);
            }

            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to free the memory allocated for the dll path in the process");   
            }
            
            remoteThreadHandle?.Close();
            
            return true;
        }  
    }
}