using System;
using System.Collections.Generic;
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
        internal static extern bool WriteProcessMemory(SafeHandle hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, uint lpNumberOfBytesWritten);
        
        [DllImport("kernel32.dll")]
        internal static extern IntPtr CreateRemoteThread(SafeHandle hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        
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
        internal static extern void RtlCreateUserThread(SafeHandle hProcess, IntPtr lpThreadSecurity, bool bCreateSuspended, uint dwStackZeroBits, IntPtr pStackReserved, IntPtr pStackCommit, IntPtr pStartAddress, IntPtr pStartParameter, out IntPtr hThread, IntPtr pClientId);
        
        [DllImport("kernel32.dll")]
        internal static extern bool VirtualQueryEx(SafeHandle hProcess, IntPtr lpAddress, out MemoryInformation lpBuffer, int dwLength);
        
        [DllImport("kernel32.dll")]
        internal static extern bool VirtualProtectEx(SafeHandle hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);
        
        [DllImport("kernel32.dll")]
        internal static extern void WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
        
        [DllImport("kernel32.dll")]
        internal static extern void CloseHandle(IntPtr hHandle);
        
        [DllImport("kernel32.dll")]
        internal static extern void VirtualFreeEx(SafeHandle hProcess, IntPtr lpAddress, int dwSize, MemoryAllocation dwFreeType);
        
        [DllImport("user32.dll")]
        internal static extern void PostMessage(IntPtr hWnd, WindowsMessage dwMsg, IntPtr wParam, IntPtr lParam);

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

        internal enum Flags
        {
            ContextControl = 0x10001
        }

        internal enum WindowsMessage
        {
            WmKeydown = 0x100
        }
        
        #endregion
        
        #region Structures
        
        [StructLayout(LayoutKind.Sequential)]
        private struct FloatingSaveArea
        {
            private readonly uint ControlWord; 
            private readonly uint StatusWord; 
            private readonly uint TagWord; 
            
            private readonly uint ErrorOffset; 
            private readonly uint ErrorSelector; 
            
            private readonly uint DataOffset;
            private readonly uint DataSelector; 
            
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)] 
            private readonly byte[] RegisterArea; 
            
            private readonly uint Cr0NpxState; 
            
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct Context
        {
            internal uint ContextFlags;
            
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
            private readonly ushort ControlWord;
            private readonly ushort StatusWord;
            private readonly byte TagWord;
            
            private readonly byte Reserved1;
            
            private readonly ushort ErrorOpcode;
            private readonly uint ErrorOffset;
            private readonly ushort ErrorSelector;
            
            private readonly ushort Reserved2;
            
            private readonly uint DataOffset;
            private readonly ushort DataSelector;
            
            private readonly ushort Reserved3;
            
            private readonly uint MxCsr;
            private readonly uint MxCsr_Mask;

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

            internal Flags ContextFlags;
            private readonly uint MxCsr;

            private readonly ushort SegCs;
            private readonly ushort SegDs;
            private readonly ushort SegEs;
            private readonly ushort SegFs;
            private readonly ushort SegGs;
            private readonly ushort SegSs;
            private readonly uint EFlags;

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
        internal struct MemoryInformation 
        {
            private readonly IntPtr BaseAddress;
            
            private readonly IntPtr AllocationBase;
            private readonly uint AllocationProtect; 
            
            internal readonly IntPtr RegionSize;
            
            private readonly uint State;
            private readonly uint Protect;
            private readonly uint Type; 
        }
        
        #endregion
    }
}