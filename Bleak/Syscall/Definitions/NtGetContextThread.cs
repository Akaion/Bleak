using Bleak.Handlers;
using Bleak.Native;
using Bleak.SafeHandle;
using Bleak.Tools;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtGetContextThread
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtGetContextThreadDefinition(SafeThreadHandle threadHandle, IntPtr contextBuffer);

        private readonly NtGetContextThreadDefinition _ntGetContextThreadDelegate;

        internal NtGetContextThread(Tools syscallTools)
        {
            _ntGetContextThreadDelegate = syscallTools.CreateDelegateForSyscall<NtGetContextThreadDefinition>();
        }

        internal IntPtr Invoke(SafeThreadHandle threadHandle)
        {
            // Store a context structure in a buffer

            var context = new Structures.Context { ContextFlags = Enumerations.ContextFlags.Control };

            var contextBuffer = MemoryTools.StoreStructureInBuffer(context);

            // Perform the syscall

            var syscallResult = _ntGetContextThreadDelegate(threadHandle, contextBuffer);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to get the context of a thread in the target process", syscallResult);
            }

            return contextBuffer;
        }
    }
}
