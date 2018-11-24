using System;
using System.Runtime.InteropServices;

namespace Simple_Injection.Etc
{
    internal static class Native
    {
        #region pinvoke

        [DllImport("kernel32.dll")]
        internal static extern IntPtr GetModuleHandle(string moduleName);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr GetProcAddress(IntPtr moduleHandle, string procName);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr VirtualAllocEx(SafeHandle processHandle, IntPtr address, int size, MemoryAllocation allocationType, MemoryProtection protection);

        [DllImport("kernel32.dll")]
        internal static extern bool WriteProcessMemory(SafeHandle processHandle, IntPtr address, byte[] buffer, int size, int bytesWritten);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr CreateRemoteThread(SafeHandle processHandle, IntPtr threadAttributes, int stackSize, IntPtr startAddress, IntPtr parameter, int creationFlags, IntPtr threadId);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr OpenThread(ThreadAccess desiredAccess, bool inheritHandle, int threadId);

        [DllImport("kernel32.dll")]
        internal static extern void SuspendThread(IntPtr threadHandle);

        [DllImport("kernel32.dll")]
        internal static extern bool GetThreadContext(IntPtr threadHandle, ref Context context);

        // x64 Overload for GetThreadContext

        [DllImport("kernel32.dll")]
        internal static extern bool GetThreadContext(IntPtr threadHandle, ref Context64 context);

        [DllImport("kernel32.dll")]
        internal static extern bool SetThreadContext(IntPtr threadHandle, ref Context context);

        // x64 Overload for SetThreadContext

        [DllImport("kernel32.dll")]
        internal static extern bool SetThreadContext(IntPtr threadHandle, ref Context64 context);

        [DllImport("kernel32.dll")]
        internal static extern void ResumeThread(IntPtr threadHandle);

        [DllImport("kernel32.dll")]
        internal static extern bool QueueUserAPC(IntPtr apc, IntPtr threadHandle, IntPtr data);

        [DllImport("ntdll.dll")]
        internal static extern void RtlCreateUserThread(SafeHandle processHandle, IntPtr threadSecurity, bool createSuspended, int stackZeroBits, IntPtr stackReserved, IntPtr stackCommit, IntPtr startAddress, IntPtr parameter, out IntPtr threadHandle, IntPtr clientId);

        [DllImport("kernel32.dll")]
        internal static extern bool VirtualQueryEx(SafeHandle processHandle, IntPtr address, out MemoryBasicInformation buffer, int length);

        [DllImport("kernel32.dll")]
        internal static extern bool VirtualProtectEx(SafeHandle processHandle, IntPtr address, int size, int newProtection, out int oldProtection);

        [DllImport("kernel32.dll")]
        internal static extern void WaitForSingleObject(IntPtr handle, int milliseconds);

        [DllImport("kernel32.dll")]
        internal static extern void CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll")]
        internal static extern void VirtualFreeEx(SafeHandle processHandle, IntPtr address, int size, MemoryAllocation freeType);

        [DllImport("user32.dll")]
        internal static extern void PostMessage(IntPtr windowHandle, WindowsMessage message, IntPtr wParameter, IntPtr lParameter);

        [DllImport("dbghelp.dll")]
        internal static extern IntPtr ImageRvaToVa(IntPtr ntHeader, IntPtr address, IntPtr rva, IntPtr lastRvaSection);

        #endregion

        #region Permissions

        [Flags]
        internal enum MemoryAllocation
        {
            Commit = 0x01000,
            Reserve = 0x02000,
            Release = 0x08000
        }

        [Flags]
        internal enum MemoryProtection
        {
            PageNoAccess = 0x01,
            PageReadOnly = 0x02,
            PageReadWrite = 0x04,
            PageWriteCopy = 0x08,
            PageExecute = 0x010,
            PageExecuteRead = 0x020,
            PageExecuteReadWrite = 0x040,
            PageExecuteWriteCopy = 0x080,
            PageNoCache = 0x0200
        }

        [Flags]
        internal enum ThreadAccess
        {
            SuspendResume = 0x02,
            GetContext = 0x08,
            SetContext = 0x010
        }

        [Flags]
        internal enum ContextFlags
        {
            ContextControl = 0x010001
        }

        [Flags]
        internal enum WindowsMessage
        {
            WmKeydown = 0x0100
        }

        [Flags]
        internal enum DataSectionFlags : uint
        {
            MemoryNotCached = 0x04000000,
            MemoryExecute = 0x020000000,
            MemoryRead = 0x040000000,
            MemoryWrite = 0x080000000
        }

        #endregion

        #region Structures

        [StructLayout(LayoutKind.Sequential)]
        private struct FloatingSaveArea
        {
            private readonly int ControlWord;
            private readonly int StatusWord;
            private readonly int TagWord;

            private readonly int ErrorOffset;
            private readonly int ErrorSelector;

            private readonly int DataOffset;
            private readonly int DataSelector;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            private readonly byte[] RegisterArea;

            private readonly int Cr0NpxState;

        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct Context
        {
            internal ContextFlags Flags;

            private readonly IntPtr Dr0;
            private readonly IntPtr Dr1;
            private readonly IntPtr Dr2;
            private readonly IntPtr Dr3;
            private readonly IntPtr Dr6;
            private readonly IntPtr Dr7;

            private readonly FloatingSaveArea FloatingSave;

            private readonly IntPtr SegGs;
            private readonly IntPtr SegFs;
            private readonly IntPtr SegEs;
            private readonly IntPtr SegDs;

            private readonly IntPtr Edi;
            private readonly IntPtr Esi;
            private readonly IntPtr Ebx;
            private readonly IntPtr Edx;
            private readonly IntPtr Ecx;
            private readonly IntPtr Eax;

            private readonly IntPtr Ebp;
            internal IntPtr Eip;
            private readonly IntPtr SegCs;
            private readonly IntPtr EFlags;
            private readonly IntPtr Esp;
            private readonly IntPtr SegSs;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            private readonly byte[] ExtendedRegisters;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct M128A
        {
            private readonly IntPtr High;
            private readonly IntPtr Low;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        private struct SaveFormat
        {
            private readonly short ControlWord;
            private readonly short StatusWord;
            private readonly byte TagWord;

            private readonly byte Reserved1;

            private readonly short ErrorOpcode;
            private readonly int ErrorOffset;
            private readonly short ErrorSelector;

            private readonly short Reserved2;

            private readonly int DataOffset;
            private readonly short DataSelector;

            private readonly short Reserved3;

            private readonly int MxCsr;
            private readonly int MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            private readonly M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            private readonly M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            private readonly byte[] Reserved4;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        internal struct Context64
        {
            private readonly IntPtr P1Home;
            private readonly IntPtr P2Home;
            private readonly IntPtr P3Home;
            private readonly IntPtr P4Home;
            private readonly IntPtr P5Home;
            private readonly IntPtr P6Home;

            internal ContextFlags Flags;
            private readonly int MxCsr;

            private readonly short SegCs;
            private readonly short SegDs;
            private readonly short SegEs;
            private readonly short SegFs;
            private readonly short SegGs;
            private readonly short SegSs;

            private readonly int EFlags;

            private readonly IntPtr Dr0;
            private readonly IntPtr Dr1;
            private readonly IntPtr Dr2;
            private readonly IntPtr Dr3;
            private readonly IntPtr Dr6;
            private readonly IntPtr Dr7;

            private readonly IntPtr Rax;
            private readonly IntPtr Rcx;
            private readonly IntPtr Rdx;
            private readonly IntPtr Rbx;
            private readonly IntPtr Rsp;
            private readonly IntPtr Rbp;
            private readonly IntPtr Rsi;
            private readonly IntPtr Rdi;
            private readonly IntPtr R8;
            private readonly IntPtr R9;
            private readonly IntPtr R10;
            private readonly IntPtr R11;
            private readonly IntPtr R12;
            private readonly IntPtr R13;
            private readonly IntPtr R14;
            private readonly IntPtr R15;
            internal IntPtr Rip;

            private readonly SaveFormat DummyUnionName;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            private readonly M128A[] VectorRegister;
            private readonly IntPtr VectorControl;

            private readonly IntPtr DebugControl;
            private readonly IntPtr LastBranchToRip;
            private readonly IntPtr LastBranchFromRip;
            private readonly IntPtr LastExceptionToRip;
            private readonly IntPtr LastExceptionFromRip;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct MemoryBasicInformation
        {
            private readonly IntPtr BaseAddress;

            private readonly IntPtr AllocationBase;
            private readonly int AllocationProtect;

            internal readonly IntPtr RegionSize;

            private readonly int State;
            private readonly int Protect;
            private readonly int Type;
        }

        [StructLayout(LayoutKind.Explicit)]
        internal struct ImageThunkData
        {
            [FieldOffset(0)]
            private readonly int ForwarderString;

            [FieldOffset(0)]
            private readonly int Function;

            [FieldOffset(0)]
            private readonly int Ordinal;

            [FieldOffset(0)]
            private readonly int AddressOfData;
        }

        #endregion
    }
}
