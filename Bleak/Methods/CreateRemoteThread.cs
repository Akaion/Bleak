using System;
using System.Diagnostics;
using System.Text;
using Jupiter;
using static Bleak.Etc.Native;

namespace Bleak.Methods
{
    internal class CreateRemoteThread
    {
        private readonly MemoryModule _memoryModule;
        
        internal CreateRemoteThread()
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
            
            // Open a handle to the process

            var processHandle = process.SafeHandle;
            
            // Create a remote thread to call load library in the process

            var remoteThreadHandle = CreateRemoteThread(processHandle, IntPtr.Zero, 0, loadLibraryAddress,dllPathAddress, 0, 0);

            if (remoteThreadHandle is null)
            {
                return false;
            }
            
            // Wait for the remote thread to finish its task
            
            WaitForSingleObject(remoteThreadHandle, int.MaxValue);
            
            // Free the memory previously allocated for the dll path

            if (!_memoryModule.FreeMemory(processId, dllPathAddress))
            {
                return false;
            }
            
            // Close the handle opened to the process
            
            processHandle.Close();
            
            // Close the handle opened to the remote thread
            
            remoteThreadHandle.Close();
            
            return true;
        }
    }
}