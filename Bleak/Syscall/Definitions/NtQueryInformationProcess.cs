using Bleak.Handlers;
using Bleak.Memory;
using Bleak.Native;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Syscall.Definitions
{
    internal class NtQueryInformationProcess
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate Enumerations.NtStatus NtQueryInformationProcessDefinition(SafeProcessHandle processHandle, Enumerations.ProcessInformationClass processInformationClass, IntPtr processInformationBuffer, ulong bufferSize, IntPtr returnLength);

        private readonly NtQueryInformationProcessDefinition _ntQueryInformationProcessDelegate;

        internal NtQueryInformationProcess(IntPtr shellcodeAddress)
        {
            _ntQueryInformationProcessDelegate = Marshal.GetDelegateForFunctionPointer<NtQueryInformationProcessDefinition>(shellcodeAddress);
        }

        internal IntPtr Invoke(SafeProcessHandle processHandle, Enumerations.ProcessInformationClass processInformationClass)
        {
            // Initialise a buffer to store the returned process information structure

            var bufferSize = processInformationClass == Enumerations.ProcessInformationClass.BasicInformation ? Marshal.SizeOf<Structures.ProcessBasicInformation>() : sizeof(ulong);

            var processInformationBuffer = LocalMemoryTools.AllocateMemoryForBuffer(bufferSize);

            // Perform the syscall

            var syscallResult = _ntQueryInformationProcessDelegate(processHandle, processInformationClass, processInformationBuffer, (ulong) bufferSize, IntPtr.Zero);

            if (syscallResult != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to query the information of the target process", syscallResult);
            }

            return processInformationBuffer;
        }
    }
}
