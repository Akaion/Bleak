using Bleak.Handlers;
using Bleak.Native;
using Bleak.SafeHandle;
using Bleak.Tools;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtCreateThreadEx
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtCreateThreadExDefinition(IntPtr threadHandleBuffer, Enumerations.ThreadAccessMask desiredAccess, IntPtr objectAttributesBuffer, SafeProcessHandle processHandle, IntPtr startAddress, IntPtr parameter, Enumerations.ThreadCreationType creationType, IntPtr stackZeroBits, IntPtr sizeOfStack, IntPtr maximumStackSize, IntPtr attributeListBuffer);

        private readonly NtCreateThreadExDefinition _ntCreateThreadExDelegate;

        internal NtCreateThreadEx(Tools syscallTools)
        {
            _ntCreateThreadExDelegate = syscallTools.CreateDelegateForSyscall<NtCreateThreadExDefinition>();
        }

        internal SafeThreadHandle Invoke(SafeProcessHandle processHandle, IntPtr startAddress, IntPtr parameter)
        {
            // Initialise a buffer to store the returned thread handle

            var threadHandleBuffer = MemoryTools.AllocateMemoryForBuffer(IntPtr.Size);

            // Perform the syscall

            const Enumerations.ThreadAccessMask desiredAccess = Enumerations.ThreadAccessMask.SpecificRightsAll | Enumerations.ThreadAccessMask.StandardRightsAll;

            var syscallResult = _ntCreateThreadExDelegate(threadHandleBuffer, desiredAccess, IntPtr.Zero, processHandle, startAddress, parameter, Enumerations.ThreadCreationType.HideFromDebugger, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to create a thread in the target process", syscallResult);
            }

            // Marshal the returned thread handle from the buffer

            var threadHandle = new SafeThreadHandle(Marshal.PtrToStructure<IntPtr>(threadHandleBuffer), true);

            MemoryTools.FreeMemoryForBuffer(threadHandleBuffer);

            return threadHandle;
        }
    }
}
