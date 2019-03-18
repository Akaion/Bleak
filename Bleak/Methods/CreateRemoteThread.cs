using Bleak.Handlers;
using Bleak.Methods.Interfaces;
using Bleak.Native;
using Bleak.Tools;
using Bleak.Wrappers;
using System;
using System.Text;

namespace Bleak.Methods
{
    internal class CreateRemoteThread : IInjectionMethod
    {
        private readonly PropertyWrapper PropertyWrapper;

        internal CreateRemoteThread(PropertyWrapper propertyWrapper)
        {
            PropertyWrapper = propertyWrapper;
        }

        public bool Call()
        {
            // Get the address of the LoadLibraryW function in the target process

            var loadLibraryAddress = NativeTools.GetFunctionAddress(PropertyWrapper, "kernel32.dll", "LoadLibraryW");

            // Allocate a buffer for the DLL path in the target process

            var dllPathBuffer = PropertyWrapper.MemoryManager.Value.AllocateMemory(PropertyWrapper.DllPath.Length, Enumerations.MemoryProtectionType.ExecuteReadWrite);

            // Write the DLL path into the buffer

            var dllPathBytes = Encoding.Unicode.GetBytes(PropertyWrapper.DllPath + "\0");

            PropertyWrapper.MemoryManager.Value.WriteMemory(dllPathBuffer, dllPathBytes);

            // Create a remote thread to call LoadLibraryW in the target process

            var remoteThreadHandle = PInvoke.CreateRemoteThread(PropertyWrapper.ProcessHandle.Value, IntPtr.Zero, 0, loadLibraryAddress, dllPathBuffer, 0, IntPtr.Zero);

            if (remoteThreadHandle is null)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to create a thread in the target process");
            }

            // Wait for the remote thread to finish its task

            PInvoke.WaitForSingleObject(remoteThreadHandle, uint.MaxValue);

            // Free the memory allocated for the buffer

            PropertyWrapper.MemoryManager.Value.FreeMemory(dllPathBuffer);

            remoteThreadHandle.Dispose();

            return true;
        }
    }
}
