using System;
using System.Runtime.InteropServices;
using static Bleak.Etc.Native;

namespace Bleak.Etc
{
    internal static class Wrapper
    {
        internal static bool WriteMemory(SafeHandle processHandle, IntPtr address, byte[] buffer)
        {
            // Change the protection of the memory region

            if (!VirtualProtectEx(processHandle, address, buffer.Length, 0x040, out var oldProtection))
            {
                return false;
            }

            // Write the buffer into the memory region

            if (!WriteProcessMemory(processHandle, address, buffer, buffer.Length, 0))
            {
                return false;
            }

            // Restore the protection of the memory region

            if (!VirtualProtectEx(processHandle, address, buffer.Length, oldProtection, out _))
            {
                return false;
            }

            return true;
        }

        internal static bool WriteMemory(SafeHandle processHandle, IntPtr address, byte[] buffer, int newProtection)
        {
            // Change the protection of the memory region

            if (!VirtualProtectEx(processHandle, address, buffer.Length, 0x040, out _))
            {
                return false;
            }

            // Write the buffer into the memory region

            if (!WriteProcessMemory(processHandle, address, buffer, buffer.Length, 0))
            {
                return false;
            }

            // Restore the protection of the memory region to the new protection

            if (!VirtualProtectEx(processHandle, address, buffer.Length, newProtection, out _))
            {
                return false;
            }

            return true;
        }
    }
}