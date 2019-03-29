using Bleak.Handlers;
using Bleak.Native;
using Bleak.Tools;
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

        internal NtOpenProcess(Tools syscallTools)
        {
            _ntOpenProcessDelegate = syscallTools.CreateDelegateForSyscall<NtOpenProcessDefinition>();
        }

        internal SafeProcessHandle Invoke(int processId)
        {
            // Initialise a buffer to store the returned process handle

            var processHandleBuffer = MemoryTools.AllocateMemoryForBuffer(IntPtr.Size);

            // Store an empty object attributes structure in a buffer

            var objectAttributesBuffer = MemoryTools.StoreStructureInBuffer(new Structures.ObjectAttributes());

            // Store a client id structure in a buffer

            var clientId = new Structures.ClientId { UniqueProcess = new IntPtr(processId), UniqueThread = IntPtr.Zero };

            var clientIdBuffer = MemoryTools.StoreStructureInBuffer(clientId);

            // Perform the syscall

            var syscallResult = _ntOpenProcessDelegate(processHandleBuffer, Enumerations.ProcessAccessMask.AllAccess, objectAttributesBuffer, clientIdBuffer);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to open a handle to the target process", syscallResult);
            }

            // Marshal the returned process handle from the buffer

            var processHandle = new SafeProcessHandle(Marshal.PtrToStructure<IntPtr>(processHandleBuffer), true);

            MemoryTools.FreeMemoryForBuffer(processHandleBuffer);

            MemoryTools.FreeMemoryForBuffer(objectAttributesBuffer);

            MemoryTools.FreeMemoryForBuffer(clientIdBuffer);

            return processHandle;
        }
    }
}
