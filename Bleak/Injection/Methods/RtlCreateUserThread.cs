using Bleak.Handlers;
using Bleak.Injection.Interfaces;
using Bleak.Injection.Objects;
using Bleak.Native;
using System;
using System.Text;

namespace Bleak.Injection.Methods
{
    internal class RtlCreateUserThread : IInjectionMethod
    {
        public bool Call(InjectionProperties injectionProperties)
        {
            // Get the address of the LoadLibraryW function in the target process

            var loadLibraryAddress = injectionProperties.RemoteProcess.GetFunctionAddress("kernel32.dll", "LoadLibraryW");

            // Write the DLL path into the target process

            var dllPathBuffer = injectionProperties.MemoryManager.AllocateVirtualMemory(IntPtr.Zero, injectionProperties.DllPath.Length, Enumerations.MemoryProtectionType.ExecuteReadWrite);

            var dllPathBytes = Encoding.Unicode.GetBytes(injectionProperties.DllPath);

            injectionProperties.MemoryManager.WriteVirtualMemory(dllPathBuffer, dllPathBytes);

            // Create a thread to call LoadLibraryW in the target process

            var ntStatus = PInvoke.RtlCreateUserThread(injectionProperties.RemoteProcess.Handle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, loadLibraryAddress, dllPathBuffer, out var remoteThreadHandle, IntPtr.Zero);

            if (ntStatus != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to create a thread in the target process", ntStatus);
            }

            PInvoke.WaitForSingleObject(remoteThreadHandle, uint.MaxValue);

            injectionProperties.MemoryManager.FreeVirtualMemory(dllPathBuffer);

            remoteThreadHandle.Dispose();

            return true;
        }
    }
}
