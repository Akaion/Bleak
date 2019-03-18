using Bleak.Native;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Bleak.Handlers
{
    internal static class ExceptionHandler
    {
        internal static void ThrowWin32Exception(string message)
        {
            // Get the error code associated with the last win32 error

            var errorCode = Marshal.GetLastWin32Error();

            throw new Win32Exception($"{message} with error code {errorCode}");
        }

        internal static void ThrowWin32Exception(string message, Enumerations.NtStatus ntStatus)
        {
            // Convert the nt status into a dos error code

            var errorCode = PInvoke.RtlNtStatusToDosError(ntStatus);

            throw new Win32Exception($"{message} with error code {errorCode}");
        }
    }
}
