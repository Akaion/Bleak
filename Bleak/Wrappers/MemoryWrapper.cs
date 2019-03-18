using Bleak.Native;
using Bleak.Syscall;
using Bleak.Tools;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace Bleak.Wrappers
{
    internal class MemoryWrapper : IDisposable
    {
        private readonly SafeProcessHandle ProcessHandle;

        private readonly SyscallManager SyscallManager;
        
        internal MemoryWrapper(SafeProcessHandle processHandle)
        {
            SyscallManager = new SyscallManager();
            
            ProcessHandle = processHandle;
        }

        public void Dispose()
        {
            SyscallManager.Dispose();
        }

        internal IntPtr AllocateMemory(int allocationSize, Enumerations.MemoryProtectionType protectionType)
        {
            return (IntPtr) SyscallManager.InvokeSyscall<Syscall.Definitions.NtAllocateVirtualMemory>(ProcessHandle, allocationSize, protectionType);
        }

        internal void FreeMemory(IntPtr baseAddress)
        {
            SyscallManager.InvokeSyscall<Syscall.Definitions.NtFreeVirtualMemory>(ProcessHandle, baseAddress);
        }

        internal Enumerations.MemoryProtectionType ProtectMemory(IntPtr baseAddress, int protectionSize, Enumerations.MemoryProtectionType newProtectionType)
        {
            return (Enumerations.MemoryProtectionType) SyscallManager.InvokeSyscall<Syscall.Definitions.NtProtectVirtualMemory>(ProcessHandle, baseAddress, protectionSize, newProtectionType);
        }

        internal byte[] ReadMemory(IntPtr baseAddress, int bytesToRead)
        {
            // Adjust the protection of the memory region in the target process

            var oldProtection = ProtectMemory(baseAddress, bytesToRead, Enumerations.MemoryProtectionType.ReadWrite);

            var bytesReadBuffer = SyscallManager.InvokeSyscall<Syscall.Definitions.NtReadVirtualMemory>(ProcessHandle, baseAddress, bytesToRead);

            // Restore the protection of the memory region in the target process

            ProtectMemory(baseAddress, bytesToRead, oldProtection);

            // Marshal the bytes read from the buffer

            var bytesRead = new byte[bytesToRead];

            Marshal.Copy((IntPtr) bytesReadBuffer, bytesRead, 0, bytesToRead);

            // Free the memory allocated for the buffer

            MemoryTools.FreeMemoryForBuffer((IntPtr) bytesReadBuffer, bytesToRead);

            return bytesRead;
        }

        internal TStructure ReadMemory<TStructure>(IntPtr baseAddress) where TStructure : struct
        {
            var structureSize = Marshal.SizeOf<TStructure>();

            // Adjust the protection of the memory region in the target process

            var oldProtection = ProtectMemory(baseAddress, structureSize, Enumerations.MemoryProtectionType.ReadWrite);

            var structureBuffer = SyscallManager.InvokeSyscall<Syscall.Definitions.NtReadVirtualMemory>(ProcessHandle, baseAddress, structureSize);

            // Restore the protection of the memory region in the target process

            ProtectMemory(baseAddress, structureSize, oldProtection);

            // Marshal the structure from the buffer

            var structure = Marshal.PtrToStructure<TStructure>((IntPtr) structureBuffer);

            // Free the memory allocated for the buffer

            MemoryTools.FreeMemoryForBuffer((IntPtr) structureBuffer, structureSize);

            return structure;
        }

        internal void WriteMemory(IntPtr baseAddress, byte[] bytesToWrite)
        {
            // Store the bytes to write in a buffer

            var bytesBuffer = GCHandle.Alloc(bytesToWrite, GCHandleType.Pinned);

            // Adjust the protection of the memory region in the target process

            var oldProtection = ProtectMemory(baseAddress, bytesToWrite.Length, Enumerations.MemoryProtectionType.ReadWrite);

            SyscallManager.InvokeSyscall<Syscall.Definitions.NtWriteVirtualMemory>(ProcessHandle, baseAddress, bytesBuffer.AddrOfPinnedObject(), bytesToWrite.Length);

            // Restore the protection of the memory region in the target process

            ProtectMemory(baseAddress, bytesToWrite.Length, oldProtection);

            // Free the memory allocated for the buffer

            bytesBuffer.Free();
        }

        internal void WriteMemory<TStructure>(IntPtr baseAddress, TStructure structureToWrite) where TStructure : struct
        {
            // Store the structure in a buffer

            var structureBuffer = MemoryTools.StoreStructureInBuffer(structureToWrite);

            var structureSize = Marshal.SizeOf<TStructure>();

            // Adjust the protection of the memory region in the target process

            var oldProtection = ProtectMemory(baseAddress, structureSize, Enumerations.MemoryProtectionType.ReadWrite);

            SyscallManager.InvokeSyscall<Syscall.Definitions.NtWriteVirtualMemory>(ProcessHandle, baseAddress, structureBuffer, structureSize);

            // Restore the protection of the memory region in the target process

            ProtectMemory(baseAddress, structureSize, oldProtection);

            // Free the memory allocated for the buffer

            MemoryTools.FreeMemoryForBuffer(structureBuffer, structureSize);
        }
    }
}
