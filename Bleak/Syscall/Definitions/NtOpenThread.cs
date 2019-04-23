using Bleak.Handlers;
using Bleak.Memory;
using Bleak.Native;
using Bleak.Native.SafeHandle;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtOpenThread
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtOpenThreadDefinition(IntPtr threadHandleBuffer, Enumerations.ThreadAccessMask desiredAccess, IntPtr objectAttributesBuffer, IntPtr clientIdBuffer);

        private readonly NtOpenThreadDefinition _ntOpenThreadDelegate;

        internal NtOpenThread(IntPtr shellcodeAddress)
        {
            _ntOpenThreadDelegate = Marshal.GetDelegateForFunctionPointer<NtOpenThreadDefinition>(shellcodeAddress);
        }
        
        internal SafeThreadHandle Invoke(int threadId)
        {
            // Initialise a buffer to store the returned thread handle

            var threadHandleBuffer = LocalMemoryTools.AllocateMemoryForBuffer(IntPtr.Size);

            // Store an empty object attributes structure in a buffer

            var objectAttributesBuffer = LocalMemoryTools.StoreStructureInBuffer(new Structures.ObjectAttributes());

            // Store a client id structure in a buffer

            var clientId = new Structures.ClientId { UniqueThread = new IntPtr(threadId) };

            var clientIdBuffer = LocalMemoryTools.StoreStructureInBuffer(clientId);

            // Perform the syscall

            var syscallResult = _ntOpenThreadDelegate(threadHandleBuffer, Enumerations.ThreadAccessMask.AllAccess, objectAttributesBuffer, clientIdBuffer);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to open a handle to a thread in the target process", syscallResult);
            }

            try
            {
                return new SafeThreadHandle(Marshal.PtrToStructure<IntPtr>(threadHandleBuffer), true);
            }

            finally
            {
                LocalMemoryTools.FreeMemoryForBuffer(threadHandleBuffer);

                LocalMemoryTools.FreeMemoryForBuffer(objectAttributesBuffer);

                LocalMemoryTools.FreeMemoryForBuffer(clientIdBuffer);
            }
        }
    }
}
