using Bleak.Handlers;
using Bleak.Native;
using Bleak.SafeHandle;
using Bleak.Tools;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtOpenThread
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtOpenThreadDefinition(IntPtr threadHandleBuffer, Enumerations.ThreadAccessMask desiredAccess, IntPtr objectAttributesBuffer, IntPtr clientIdBuffer);

        private readonly NtOpenThreadDefinition _ntOpenThreadDelegate;

        internal NtOpenThread(Tools syscallTools)
        {
            _ntOpenThreadDelegate = syscallTools.CreateDelegateForSyscall<NtOpenThreadDefinition>();
        }

        internal SafeThreadHandle Invoke(int threadId)
        {
            // Initialise a buffer to store the returned thread handle

            var threadHandleBuffer = MemoryTools.AllocateMemoryForBuffer(IntPtr.Size);

            // Store an empty object attributes structure in a buffer

            var objectAttributesBuffer = MemoryTools.StoreStructureInBuffer(new Structures.ObjectAttributes());

            // Store a client id structure in a buffer

            var clientId = new Structures.ClientId { UniqueThread = new IntPtr(threadId) };

            var clientIdBuffer = MemoryTools.StoreStructureInBuffer(clientId);

            // Perform the syscall

            var syscallResult = _ntOpenThreadDelegate(threadHandleBuffer, Enumerations.ThreadAccessMask.AllAccess, objectAttributesBuffer, clientIdBuffer);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to open a handle to a thread in the target process", syscallResult);
            }

            // Marshal the returned thread handle from the buffer

            var threadHandle = new SafeThreadHandle(Marshal.PtrToStructure<IntPtr>(threadHandleBuffer), true);

            MemoryTools.FreeMemoryForBuffer(threadHandleBuffer);

            MemoryTools.FreeMemoryForBuffer(objectAttributesBuffer);

            MemoryTools.FreeMemoryForBuffer(clientIdBuffer);

            return threadHandle;
        }
    }
}
