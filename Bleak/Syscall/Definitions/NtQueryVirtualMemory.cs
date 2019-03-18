using Bleak.Native;
using Bleak.Handlers;
using Bleak.Tools;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtQueryVirtualMemory : IDisposable
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtQueryVirtualMemoryDefinition(SafeProcessHandle processHandle, IntPtr baseAddress, Enumerations.MemoryInformationClass memoryInformationClass, IntPtr memoryInformationBuffer, ulong bufferSize, IntPtr returnLengthBuffer);

        private readonly NtQueryVirtualMemoryDefinition NtQueryVirtualMemoryDelegate;

        private readonly Tools SyscallTools;

        internal NtQueryVirtualMemory(Tools syscallTools)
        {
            SyscallTools = syscallTools;

            NtQueryVirtualMemoryDelegate = SyscallTools.CreateDelegateForSyscall<NtQueryVirtualMemoryDefinition>();
        }

        public void Dispose()
        {
            SyscallTools.FreeMemoryForSyscall(NtQueryVirtualMemoryDelegate);
        }

        internal IntPtr Invoke(SafeProcessHandle processHandle, IntPtr baseAddress)
        {
            // Initialise a buffer to store the returned memory basic information structure in

            var memoryBasicInformationBuffer = MemoryTools.AllocateMemoryForBuffer(Marshal.SizeOf<Structures.MemoryBasicInformation>());

            // Perform the syscall

            var syscallResult = NtQueryVirtualMemoryDelegate(processHandle, baseAddress, Enumerations.MemoryInformationClass.BasicInformation, memoryBasicInformationBuffer, (ulong) Marshal.SizeOf<Structures.MemoryBasicInformation>(), IntPtr.Zero);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to query memory in the target process", syscallResult);
            }

            return memoryBasicInformationBuffer;
        }
    }
}
