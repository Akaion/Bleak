using Bleak.Native;
using Bleak.Handlers;
using Bleak.Tools;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtOpenProcess : IDisposable
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtOpenProcessDefinition(IntPtr processHandleBuffer, Enumerations.ProcessAccessMask desiredAccess, IntPtr objectAttributesBuffer, IntPtr clientIdBuffer);

        private readonly NtOpenProcessDefinition NtOpenProcessDelegate;

        private readonly Tools SyscallTools;

        internal NtOpenProcess(Tools syscallTools)
        {
            SyscallTools = syscallTools;

            NtOpenProcessDelegate = SyscallTools.CreateDelegateForSyscall<NtOpenProcessDefinition>();
        }

        public void Dispose()
        {
            SyscallTools.FreeMemoryForSyscall(NtOpenProcessDelegate);
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

            var syscallResult = NtOpenProcessDelegate(processHandleBuffer, Enumerations.ProcessAccessMask.AllAccess, objectAttributesBuffer, clientIdBuffer);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to open a handle to the target process", syscallResult);
            }

            // Marshal the returned process handle from the buffer

            var processHandle = Marshal.PtrToStructure<IntPtr>(processHandleBuffer);

            // Convert the process handle into safe handle

            var safeProcessHandle = new SafeProcessHandle(processHandle, true);

            // Free the memory allocated for the buffers

            MemoryTools.FreeMemoryForBuffer(processHandleBuffer, IntPtr.Size);

            MemoryTools.FreeMemoryForBuffer(objectAttributesBuffer, Marshal.SizeOf<Structures.ObjectAttributes>());

            MemoryTools.FreeMemoryForBuffer(clientIdBuffer, Marshal.SizeOf<Structures.ClientId>());

            return safeProcessHandle;
        }
    }
}
