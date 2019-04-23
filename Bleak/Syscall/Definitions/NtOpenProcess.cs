using Bleak.Handlers;
using Bleak.Memory;
using Bleak.Native;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtOpenProcess
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtOpenProcessDefinition(IntPtr processHandleBuffer, Enumerations.ProcessAccessMask desiredAccess, IntPtr objectAttributesBuffer, IntPtr clientIdBuffer);

        private readonly NtOpenProcessDefinition _ntOpenProcessDelegate;

        internal NtOpenProcess(IntPtr shellcodeAddress)
        {
            _ntOpenProcessDelegate = Marshal.GetDelegateForFunctionPointer<NtOpenProcessDefinition>(shellcodeAddress);
        }

        internal SafeProcessHandle Invoke(int processId)
        {
            // Initialise a buffer to store the returned process handle

            var processHandleBuffer = LocalMemoryTools.AllocateMemoryForBuffer(IntPtr.Size);

            // Store an empty object attributes structure in a buffer

            var objectAttributesBuffer = LocalMemoryTools.StoreStructureInBuffer(new Structures.ObjectAttributes());

            // Store a client id structure in a buffer

            var clientId = new Structures.ClientId { UniqueProcess = new IntPtr(processId), UniqueThread = IntPtr.Zero };

            var clientIdBuffer = LocalMemoryTools.StoreStructureInBuffer(clientId);

            // Perform the syscall

            var syscallResult = _ntOpenProcessDelegate(processHandleBuffer, Enumerations.ProcessAccessMask.AllAccess, objectAttributesBuffer, clientIdBuffer);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to open a handle to the target process", syscallResult);
            }

            try
            {
                return new SafeProcessHandle(Marshal.PtrToStructure<IntPtr>(processHandleBuffer), true);
            }

            finally
            {
                LocalMemoryTools.FreeMemoryForBuffer(processHandleBuffer);

                LocalMemoryTools.FreeMemoryForBuffer(objectAttributesBuffer);

                LocalMemoryTools.FreeMemoryForBuffer(clientIdBuffer);
            }
        }
    }
}
