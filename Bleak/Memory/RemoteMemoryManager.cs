using Bleak.Native;
using Bleak.Syscall;
using Bleak.Syscall.Definitions;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Memory
{
    internal class RemoteMemoryManager
    {
        private readonly SafeProcessHandle _processHandle;

        private readonly SyscallManager _syscallManager;

        internal RemoteMemoryManager(SafeProcessHandle processHandle, SyscallManager syscallManager)
        {
            _processHandle = processHandle;

            _syscallManager = syscallManager;
        }

        internal IntPtr AllocateVirtualMemory(IntPtr baseAddress, int size, Enumerations.MemoryProtectionType protectionType)
        {
            return (IntPtr) _syscallManager.InvokeSyscall<NtAllocateVirtualMemory>(_processHandle, baseAddress, size, protectionType);
        }

        internal void FreeVirtualMemory(IntPtr baseAddress)
        {
            _syscallManager.InvokeSyscall<NtFreeVirtualMemory>(_processHandle, baseAddress);
        }

        internal Enumerations.MemoryProtectionType ProtectVirtualMemory(IntPtr baseAddress, int size, Enumerations.MemoryProtectionType newProtectionType)
        {
            return (Enumerations.MemoryProtectionType) _syscallManager.InvokeSyscall<NtProtectVirtualMemory>(_processHandle, baseAddress, size, newProtectionType);
        }

        internal byte[] ReadVirtualMemory(IntPtr baseAddress, int bytesToRead)
        {
            // Adjust the protection of the memory region to ensure it has read privileges

            var oldProtectionType = ProtectVirtualMemory(baseAddress, bytesToRead, Enumerations.MemoryProtectionType.ReadWrite);

            // Read the specified number of bytes from the memory region

            var bytesReadBuffer = (IntPtr) _syscallManager.InvokeSyscall<NtReadVirtualMemory>(_processHandle, baseAddress, bytesToRead);

            var bytesRead = new byte[bytesToRead];

            Marshal.Copy(bytesReadBuffer, bytesRead, 0, bytesToRead);

            // Restore the old protection of the memory region

            ProtectVirtualMemory(baseAddress, bytesToRead, oldProtectionType);

            LocalMemoryTools.FreeMemoryForBuffer(bytesReadBuffer);

            return bytesRead;
        }

        internal TStructure ReadVirtualMemory<TStructure>(IntPtr baseAddress) where TStructure : struct
        {
            // Read the bytes of the structure from the memory region

            var structureBytes = ReadVirtualMemory(baseAddress, Marshal.SizeOf<TStructure>());

            // Marshal the bytes into a structure

            var structureBytesBuffer = LocalMemoryTools.StoreBytesInBuffer(structureBytes);

            try
            {
                return Marshal.PtrToStructure<TStructure>(structureBytesBuffer);
            }

            finally
            {
                LocalMemoryTools.FreeMemoryForBuffer(structureBytesBuffer);
            }
        }

        internal void WriteVirtualMemory(IntPtr baseAddress, byte[] bytesToWrite)
        {
            // Store the bytes to write in a buffer

            var bytesToWriteBuffer = LocalMemoryTools.StoreBytesInBuffer(bytesToWrite);

            // Adjust the protection of the memory region to ensure it has write privileges

            var oldProtectionType = ProtectVirtualMemory(baseAddress, bytesToWrite.Length, Enumerations.MemoryProtectionType.ReadWrite);

            // Write the bytes into the memory region

            _syscallManager.InvokeSyscall<NtWriteVirtualMemory>(_processHandle, baseAddress, bytesToWriteBuffer, bytesToWrite.Length);

            // Restore the old protection of the memory region

            ProtectVirtualMemory(baseAddress, bytesToWrite.Length, oldProtectionType);

            LocalMemoryTools.FreeMemoryForBuffer(bytesToWriteBuffer);
        }

        internal void WriteVirtualMemory<TStructure>(IntPtr baseAddress, TStructure structureToWrite) where TStructure : struct
        {
            // Store the structure to write in a buffer

            var structureBuffer = LocalMemoryTools.StoreStructureInBuffer(structureToWrite);

            // Marshal the structure into bytes

            var structureBytes = new byte[Marshal.SizeOf<TStructure>()];

            Marshal.Copy(structureBuffer, structureBytes, 0, Marshal.SizeOf<TStructure>());

            // Write the structure into the memory region

            WriteVirtualMemory(baseAddress, structureBytes);
        }
    }
}
