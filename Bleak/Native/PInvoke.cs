using Bleak.Native.SafeHandle;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Native
{
    internal static class PInvoke
    {
        // kernel32.dll imports

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool IsWow64Process(SafeProcessHandle processHandle, out bool isWow64Process);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr GetProcAddress(IntPtr moduleHandle, string functionName);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr VirtualAlloc(IntPtr baseAddress, uint allocationSize, Enumerations.MemoryAllocationType allocationType, Enumerations.MemoryProtectionType protectionType);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualFree(IntPtr baseAddress, uint freeSize, Enumerations.MemoryFreeType freeType);

        [DllImport("kernel32.dll")]
        internal static extern void WaitForSingleObject(SafeThreadHandle handle, uint millisecondsToWait);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint Wow64GetThreadContext(SafeThreadHandle threadHandle, IntPtr contextBuffer);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint Wow64SetThreadContext(SafeThreadHandle threadHandle, IntPtr contextBuffer);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int Wow64SuspendThread(SafeThreadHandle threadHandle);

        // ntdll.dll imports

        [DllImport("ntdll.dll")]
        internal static extern Enumerations.NtStatus RtlCreateUserThread(SafeProcessHandle processHandle, IntPtr securityDescriptorBuffer, bool createSuspended, ulong stackZeroBits, IntPtr stackReserved, IntPtr stackCommit, IntPtr startAddress, IntPtr parameter, out SafeThreadHandle threadHandle, IntPtr clientIdBuffer);

        [DllImport("ntdll.dll")]
        internal static extern ulong RtlNtStatusToDosError(Enumerations.NtStatus ntStatus);

        [DllImport("ntdll.dll")]
        internal static extern void RtlZeroMemory(IntPtr baseAddress, uint sizeToZero);

        // user32.dll functions

        [DllImport("user32.dll")]
        internal static extern void SwitchToThisWindow(IntPtr windowHandle, bool altTab);
    }
}
