using System;
using System.Runtime.InteropServices;

namespace Simple_Injection.Etc
{
    public static class Native
    {
        #region Api Imports
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessPrivileges dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, MemoryAllocation flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint SuspendThread(IntPtr hThread);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetThreadContext(IntPtr hThread, ref Context lpContext);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetThreadContext(IntPtr hThread, ref Context lpContext);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void ResumeThread(IntPtr hThread);
        
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern void WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void CloseHandle(IntPtr handle);
        
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern void VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, MemoryAllocation dwFreeType);

        #endregion
        
        #region Permissions

        public enum ProcessPrivileges
        {
            CreateThread = 0x02,
            QueryInformation = 0x0400,
            VmOperation = 0x08,
            VmWrite = 0x20,
            VmRead = 0x10,
            AllAccess = CreateThread | QueryInformation | VmOperation | VmWrite | VmRead
            
        }
        
        public enum MemoryAllocation
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Release = 0x8000,
            AllAccess = Commit | Reserve
        }

        public enum MemoryProtection
        {
            PageReadWrite = 0x04,
            PageExecuteReadWrite = 0x40
        }

        public enum ThreadAccess
        {
            SuspendResume = 0x02,
            GetContext = 0x08,
            SetContext = 0x010,
            AllAccess = SuspendResume | GetContext | SetContext
        }

        public enum Flags
        {
            Contexti386 = 0x10000,
            ContextControl = Contexti386 | 0x01
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
        public struct Context
        {
            public uint ContextFlags;
            
            private readonly uint Dr0;
            private readonly uint Dr1;
            private readonly uint Dr2;
            private readonly uint Dr3;
            private readonly uint Dr6;
            private readonly uint Dr7;
            
            private readonly FloatingSaveArea FloatingSave;
            
            private readonly uint SegGs;
            private readonly uint SegFs;
            private readonly uint SegEs;
            private readonly uint SegDs;
            
            private readonly uint Edi;
            private readonly uint Esi;
            private readonly uint Ebx;
            private readonly uint Edx;
            private readonly uint Ecx;
            private readonly uint Eax;
            
            private readonly uint Ebp;
            public uint Eip;
            private readonly uint SegCs;
            private readonly uint EFlags;
            private readonly uint Esp;
            private readonly uint SegSs;
            
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            private readonly byte[] ExtendedRegisters;
        }
        
        #endregion
    }
}