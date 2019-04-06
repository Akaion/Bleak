using Bleak.Native;
using Bleak.Syscall;
using Bleak.Syscall.Definitions;
using Bleak.Tools;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Memory
{
    internal class MemoryManager
    {
        private readonly SafeProcessHandle _processHandle;

        private readonly SyscallManager _syscallManager;

        internal MemoryManager(SafeProcessHandle processHandle, SyscallManager syscallManager)
        {
            _processHandle = processHandle;

            _syscallManager = syscallManager;
        }

        internal IntPtr AllocateVirtualMemory(int allocationSize, Enumerations.MemoryProtectionType protectionType)
        {
            return (IntPtr) _syscallManager.InvokeSyscall<NtAllocateVirtualMemory>(_processHandle, allocationSize, protectionType);
        }

        internal void FreeVirtualMemory(IntPtr baseAddress)
        {
            _syscallManager.InvokeSyscall<NtFreeVirtualMemory>(_processHandle, baseAddress);
        }

        internal Enumerations.MemoryProtectionType ProtectVirtualMemory(IntPtr baseAddress, int protectionSize, Enumerations.MemoryProtectionType newProtectionType)
        {
            return (Enumerations.MemoryProtectionType) _syscallManager.InvokeSyscall<NtProtectVirtualMemory>(_processHandle, baseAddress, protectionSize, newProtectionType);
        }

        internal byte[] ReadVirtualMemory(IntPtr baseAddress, int bytesToRead)
        {
            // Adjust the protection of the memory region to ensure it has read privileges

            var oldProtectionType = ProtectVirtualMemory(baseAddress, bytesToRead, Enumerations.MemoryProtectionType.ReadWrite);

            // Read the specified number of bytes from the memory region

            var bytesReadBuffer = (IntPtr) _syscallManager.InvokeSyscall<NtReadVirtualMemory>(_processHandle, baseAddress, bytesToRead);

            var bytesRead = new byte[bytesToRead];

            Marshal.Copy(bytesReadBuffer, bytesRead, 0, bytesToRead);

            // Restore the protection of the memory region

            ProtectVirtualMemory(baseAddress, bytesToRead, oldProtectionType);

            MemoryTools.FreeMemoryForBuffer(bytesReadBuffer);

            return bytesRead;
        }

        internal TStructure ReadVirtualMemory<TStructure>(IntPtr baseAddress) where TStructure : struct
        {
            // Read the bytes of the structure from the memory region

            var structureBytes = ReadVirtualMemory(baseAddress, Marshal.SizeOf<TStructure>());

            // Marshal the bytes into a structure

            var structureBytesBuffer = MemoryTools.StoreBytesInBuffer(structureBytes);

            var structure = Marshal.PtrToStructure<TStructure>(structureBytesBuffer);

            MemoryTools.FreeMemoryForBuffer(structureBytesBuffer);

            return structure;
        }

        internal void WriteVirtualMemory(IntPtr baseAddress, byte[] bytesToWrite)
        {
            // Store the bytes to write in a buffer

            var bytesBuffer = MemoryTools.StoreBytesInBuffer(bytesToWrite);

            // Adjust the protection of the memory region to ensure it has write privileges

            var oldProtectionType = ProtectVirtualMemory(baseAddress, bytesToWrite.Length, Enumerations.MemoryProtectionType.ReadWrite);

            // Write the bytes into the memory region

            _syscallManager.InvokeSyscall<NtWriteVirtualMemory>(_processHandle, baseAddress, bytesBuffer, bytesToWrite.Length);

            // Restore the protection of the memory region

            ProtectVirtualMemory(baseAddress, bytesToWrite.Length, oldProtectionType);

            MemoryTools.FreeMemoryForBuffer(bytesBuffer);
        }

        internal void WriteVirtualMemory<TStructure>(IntPtr baseAddress, TStructure structureToWrite) where TStructure : struct
        {
            // Store the structure in a buffer

            var structureBuffer = MemoryTools.StoreStructureInBuffer(structureToWrite);

            // Convert the structure into bytes

            var structureSize = Marshal.SizeOf<TStructure>();

            var structureBytes = new byte[structureSize];

            Marshal.Copy(structureBuffer, structureBytes, 0, structureSize);

            // Write the bytes of the structure into the target process

            WriteVirtualMemory(baseAddress, structureBytes);
        }
    }
}
