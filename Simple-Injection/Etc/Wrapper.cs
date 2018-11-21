using System;
using System.IO;
using System.Runtime.InteropServices;
using static Simple_Injection.Etc.Native;

namespace Simple_Injection.Etc
{
    internal static class Wrapper
    {
        internal static byte[] ReadMemory(SafeHandle processHandle, IntPtr memoryPointer, int size)
        {
            var buffer = new byte[size];
            
            // Change the protection of the memory region

            VirtualProtectEx(processHandle, memoryPointer, buffer.Length, 0x40, out var oldProtection);
            
            // Read from the memory region into the buffer

            ReadProcessMemory(processHandle, memoryPointer, buffer, buffer.Length, 0);
            
            // Restore the protection of the memory region

            VirtualProtectEx(processHandle, memoryPointer, buffer.Length, oldProtection, out _);

            return buffer;
        }

        internal static TStructure ReadMemory<TStructure>(SafeHandle processHandle, IntPtr memoryPointer)
        {
            // Get the size of the structure
            
            var size = Marshal.SizeOf(typeof(TStructure));

            // Read the bytes from the memory region
            
            var buffer = ReadMemory(processHandle, memoryPointer, size);

            // Pin the buffer
            
            var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);

            // Convert the bytes into a structure
            
            var structure = (TStructure) Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(TStructure));
            
            // Unpin the buffer
            
            handle.Free();

            return structure;
        }
        
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