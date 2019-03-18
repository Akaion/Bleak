using Bleak.Native;
using Bleak.SafeHandle;
using Bleak.Handlers;
using Bleak.Tools;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtCreateThreadEx : IDisposable
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtCreateThreadExDefinition(IntPtr threadHandleBuffer, Enumerations.ThreadAccessMask desiredAccess, IntPtr objectAttributesBuffer, SafeProcessHandle processHandle, IntPtr startAddress, IntPtr parameter, Enumerations.ThreadCreationType creationType, IntPtr stackZeroBits, IntPtr sizeOfStack, IntPtr maximumStackSize, IntPtr attributeListBuffer);

        private readonly NtCreateThreadExDefinition NtCreateThreadExDelegate;

        private readonly Tools SyscallTools;

        internal NtCreateThreadEx(Tools syscallTools)
        {
            SyscallTools = syscallTools;

            NtCreateThreadExDelegate = SyscallTools.CreateDelegateForSyscall<NtCreateThreadExDefinition>();
        }

        public void Dispose()
        {
            SyscallTools.FreeMemoryForSyscall(NtCreateThreadExDelegate);
        }

        internal SafeThreadHandle Invoke(SafeProcessHandle processHandle, IntPtr startAddress, IntPtr parameter)
        {
            // Initialise a buffer to store the returned thread handle

            var threadHandleBuffer = MemoryTools.AllocateMemoryForBuffer(IntPtr.Size);

            // Perform the syscall

            const Enumerations.ThreadAccessMask desiredAccess = Enumerations.ThreadAccessMask.SpecificRightsAll | Enumerations.ThreadAccessMask.StandardRightsAll;

            var syscallResult = NtCreateThreadExDelegate(threadHandleBuffer, desiredAccess, IntPtr.Zero, processHandle, startAddress, parameter, Enumerations.ThreadCreationType.HideFromDebugger, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to create a thread in the target process", syscallResult);
            }

            // Marshal the returned thread handle from the buffer

            var threadHandle = Marshal.PtrToStructure<IntPtr>(threadHandleBuffer);

            // Convert the thread handle into a safe handle

            var safeThreadHandle = new SafeThreadHandle(threadHandle, true);

            // Free the memory allocated for the buffer

            MemoryTools.FreeMemoryForBuffer(threadHandleBuffer, IntPtr.Size);
            
            return safeThreadHandle;
        }
    }
}
