using System;
using System.Runtime.InteropServices;
using static Simple_Injection.Etc.Native;

namespace Simple_Injection.Etc
{
    internal static class Wrapper
    { 
        internal static bool WriteMemory(SafeHandle processHandle, IntPtr memoryPointer, byte[] buffer)
        {
            // Change the protection of the memory region

            if (!VirtualProtectEx(processHandle, memoryPointer, buffer.Length, 0x40, out var oldProtection))
            {
                return false;
            }

            // Write the buffer into the memory region

            if (!WriteProcessMemory(processHandle, memoryPointer, buffer, buffer.Length, 0))
            {
                return false;
            }

            // Restore the protection of the memory region

            if (!VirtualProtectEx(processHandle, memoryPointer, buffer.Length, oldProtection, out _))
            {
                return false;
            }

            return true;
        }
        
        internal static bool WriteMemory(SafeHandle processHandle, IntPtr memoryPointer, byte[] buffer, int newProtection)
        {
            // Change the protection of the memory region

            if (!VirtualProtectEx(processHandle, memoryPointer, buffer.Length, 0x40, out _))
            {
                return false;
            }

            // Write the buffer into the memory region

            if (!WriteProcessMemory(processHandle, memoryPointer, buffer, buffer.Length, 0))
            {
                return false;
            }

            // Restore the protection of the memory region to the new protection

            if (!VirtualProtectEx(processHandle, memoryPointer, buffer.Length, newProtection, out _))
            {
                return false;
            }

            return true;
        }
    }
}