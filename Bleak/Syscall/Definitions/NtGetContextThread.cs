using Bleak.Handlers;
using Bleak.Memory;
using Bleak.Native;
using Bleak.Native.SafeHandle;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtGetContextThread
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtGetContextThreadDefinition(SafeThreadHandle threadHandle, IntPtr contextBuffer);

        private readonly NtGetContextThreadDefinition _ntGetContextThreadDelegate;

        internal NtGetContextThread(IntPtr shellcodeAddress)
        {
            _ntGetContextThreadDelegate = Marshal.GetDelegateForFunctionPointer<NtGetContextThreadDefinition>(shellcodeAddress);
        }

        internal IntPtr Invoke(SafeThreadHandle threadHandle)
        {
            // Store a context structure in a buffer

            IntPtr contextBuffer;

            if (Environment.Is64BitProcess)
            {
                var context = new Structures.Context { ContextFlags = Enumerations.ContextFlags.Control };

                contextBuffer = LocalMemoryTools.StoreStructureInBuffer(context);
            }

            else
            {
                var context = new Structures.Wow64Context { ContextFlags = Enumerations.ContextFlags.Control };

                contextBuffer = LocalMemoryTools.StoreStructureInBuffer(context);
            }

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
