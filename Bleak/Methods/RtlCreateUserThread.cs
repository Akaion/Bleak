using Bleak.Handlers;
using Bleak.Native;
using Bleak.Wrappers;
using System;
using System.Text;

namespace Bleak.Methods
{
    internal class RtlCreateUserThread
    {
        private readonly PropertyWrapper _propertyWrapper;

        internal RtlCreateUserThread(PropertyWrapper propertyWrapper)
        {
            _propertyWrapper = propertyWrapper;
        }

        internal bool Call()
        {
            // Get the address of the LoadLibraryW function

            var loadLibraryAddress = _propertyWrapper.TargetProcess.GetFunctionAddress("kernel32.dll", "LoadLibraryW");

            // Write the DLL path into the target process

            var dllPathBuffer = _propertyWrapper.MemoryManager.AllocateVirtualMemory(_propertyWrapper.DllPath.Length, Enumerations.MemoryProtectionType.ExecuteReadWrite);

            var dllPathBytes = Encoding.Unicode.GetBytes(_propertyWrapper.DllPath + "\0");

            _propertyWrapper.MemoryManager.WriteVirtualMemory(dllPathBuffer, dllPathBytes);

            // Create a thread to call LoadLibraryW in the target process

            var ntStatus = PInvoke.RtlCreateUserThread(_propertyWrapper.TargetProcess.ProcessHandle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, loadLibraryAddress, dllPathBuffer, out var remoteThreadHandle, IntPtr.Zero);

            if (ntStatus != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to create a thread in the target process", ntStatus);
            }

            PInvoke.WaitForSingleObject(remoteThreadHandle, uint.MaxValue);

            _propertyWrapper.MemoryManager.FreeVirtualMemory(dllPathBuffer);

            remoteThreadHandle.Dispose();

            return true;
        }
    }
}
