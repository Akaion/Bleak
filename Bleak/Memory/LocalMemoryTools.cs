using Bleak.Handlers;
using Bleak.Native;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Memory
{
    internal static class LocalMemoryTools
    {
        internal static IntPtr AllocateMemoryForBuffer(int allocationSize)
        {
            // Allocate memory for a buffer in the local process

            const Enumerations.MemoryAllocationType allocationType = Enumerations.MemoryAllocationType.Commit | Enumerations.MemoryAllocationType.Reserve;

            var buffer = PInvoke.VirtualAlloc(IntPtr.Zero, (uint) allocationSize, allocationType, Enumerations.MemoryProtectionType.ExecuteReadWrite);

            if (buffer == IntPtr.Zero)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to allocate memory in the local process");
            }

            // Zero the memory in the buffer

            PInvoke.RtlZeroMemory(buffer, (uint) allocationSize);

            return buffer;
        }

        internal static void FreeMemoryForBuffer(IntPtr bufferAddress)
        {
            // Free the memory allocated for the buffer

            if (!PInvoke.VirtualFree(bufferAddress, 0, Enumerations.MemoryFreeType.Release))
            {
                ExceptionHandler.ThrowWin32Exception("Failed to free memory in the local process");
            }
        }

        internal static IntPtr StoreBytesInBuffer(byte[] bytes)
        {
            // Allocate memory for a buffer to store the bytes

            var bytesBuffer = AllocateMemoryForBuffer(bytes.Length);

            // Copy the bytes into the buffer

            Marshal.Copy(bytes, 0, bytesBuffer, bytes.Length);

            return bytesBuffer;
        }

        internal static IntPtr StoreStructureInBuffer<TStructure>(TStructure structure) where TStructure : struct
        {
            // Allocate memory for a buffer to store the structure

            var structureBuffer = AllocateMemoryForBuffer(Marshal.SizeOf<TStructure>());

            // Marshal the structure into the buffer

            Marshal.StructureToPtr(structure, structureBuffer, false);

            return structureBuffer;
        }
    }
}
