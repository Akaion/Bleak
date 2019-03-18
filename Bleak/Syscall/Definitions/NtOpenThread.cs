using Bleak.Native;
using Bleak.SafeHandle;
using Bleak.Handlers;
using Bleak.Tools;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtOpenThread : IDisposable
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtOpenThreadDefinition(IntPtr threadHandleBuffer, Enumerations.ThreadAccessMask desiredAccess, IntPtr objectAttributesBuffer, IntPtr clientIdBuffer);

        private readonly NtOpenThreadDefinition NtOpenThreadDelegate;

        private readonly Tools SyscallTools;

        internal NtOpenThread(Tools syscallTools)
        {
            SyscallTools = syscallTools;

            NtOpenThreadDelegate = SyscallTools.CreateDelegateForSyscall<NtOpenThreadDefinition>();
        }

        public void Dispose()
        {
            SyscallTools.FreeMemoryForSyscall(NtOpenThreadDelegate);
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

            var syscallResult = NtOpenThreadDelegate(threadHandleBuffer, Enumerations.ThreadAccessMask.AllAccess, objectAttributesBuffer, clientIdBuffer);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to open a handle to a thread in the target process", syscallResult);
            }

            // Marshal the returned thread handle from the buffer

            var threadHandle = Marshal.PtrToStructure<IntPtr>(threadHandleBuffer);

            // Convert the thread handle into a safe handle

            var safeThreadHandle = new SafeThreadHandle(threadHandle, true);

            // Free the memory allocated for the buffers

            MemoryTools.FreeMemoryForBuffer(threadHandleBuffer, IntPtr.Size);

            MemoryTools.FreeMemoryForBuffer(objectAttributesBuffer, Marshal.SizeOf<Structures.ObjectAttributes>());

            MemoryTools.FreeMemoryForBuffer(clientIdBuffer, Marshal.SizeOf<Structures.ClientId>());

            return safeThreadHandle;
        }
    }
}
