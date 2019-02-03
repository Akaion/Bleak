using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Bleak.Etc
{
    internal static class Native
    {
        #region pinvoke
        
        // kernel32.dll imports
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr handle);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern SafeThreadHandle CreateRemoteThread(SafeProcessHandle processHandle, IntPtr threadAttributes, int stackSize, IntPtr startAddress, IntPtr parameter, int creationFlags, int threadId);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr CreateToolhelp32Snapshot(SnapshotFlags flags, uint processId);        
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetThreadContext(SafeThreadHandle threadHandle, IntPtr context);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool IsWow64Process(SafeProcessHandle processHandle, out bool isWow64Process);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool Module32First(IntPtr snapshotHandle, IntPtr moduleEntry);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool Module32Next(IntPtr snapshotHandle, IntPtr moduleEntry);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern SafeThreadHandle OpenThread(ThreadAccess desiredAccess, bool inheritHandle, int threadId);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool QueueUserAPC(IntPtr apc, SafeThreadHandle threadHandle, IntPtr data);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int ResumeThread(SafeThreadHandle threadHandle);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool SetThreadContext(SafeThreadHandle threadHandle, IntPtr context);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int SuspendThread(SafeThreadHandle threadHandle);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualQueryEx(SafeProcessHandle processHandle, IntPtr baseAddress, out MemoryBasicInformation buffer, int length);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern void WaitForSingleObject(SafeHandle handle, int milliseconds);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool Wow64GetThreadContext(SafeThreadHandle threadHandle, IntPtr wow64Context);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool Wow64SetThreadContext(SafeThreadHandle threadHandle, IntPtr wow64Context);
        
        // dbghelp.dll imports
        
        [DllImport("dbghelp.dll", SetLastError = true)]
        internal static extern IntPtr ImageRvaToVa(IntPtr ntHeader, IntPtr address, IntPtr rva, IntPtr lastRvaSection);
        
        // ntdll.dll imports
        
        [DllImport("ntdll.dll", SetLastError = true)]
        internal static extern void NtCreateThreadEx(out SafeThreadHandle threadHandle, AccessMask desiredAccess, IntPtr objectAttributes, SafeProcessHandle processHandle, IntPtr startAddress, IntPtr parameter, CreationFlags creationFlags, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList);
        
        [DllImport("ntdll.dll", SetLastError = true)]
        internal static extern void NtQueryInformationProcess(SafeProcessHandle processHandle, int processInformationClass, IntPtr buffer, int bufferSize, int returnLength);
        
        [DllImport("ntdll.dll", SetLastError = true)]
        internal static extern void RtlCreateUserThread(SafeProcessHandle processHandle, IntPtr threadSecurity, bool createSuspended, int stackZeroBits, IntPtr stackReserved, IntPtr stackCommit, IntPtr startAddress, IntPtr parameter, out SafeThreadHandle threadHandle, int clientId);
        
        [DllImport("ntdll.dll", SetLastError = true)]
        internal static extern void ZwCreateThreadEx(out SafeThreadHandle threadHandle, AccessMask desiredAccess, IntPtr objectAttributes, SafeProcessHandle processHandle, IntPtr startAddress, IntPtr parameter, CreationFlags creationFlags, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList);
        
        // user32.dll imports
        
        [DllImport("user32.dll", SetLastError = true)]
        internal static extern void SwitchToThisWindow(IntPtr windowHandle, bool altTab);
        
        #endregion
        
        #region Enumerations
        
        [Flags]
        internal enum AccessMask
        {
            SpecificRightsAll = 0x0FFFF,
            StandardRightsAll = 0x01F0000
        }
        
        [Flags]
        internal enum ContextFlags
        {
            ContextControl = 0x010001
        }
        
        [Flags]
        internal enum CreationFlags
        {
            HideFromDebugger = 0x04
        }
        
        [Flags]
        internal enum DataSectionFlags : uint
        {
            MemoryNotCached = 0x04000000,
            MemoryExecute = 0x020000000,
            MemoryRead = 0x040000000,
            MemoryWrite = 0x080000000
        }
        
        [Flags]
        internal enum MemoryProtection
        {
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            Execute = 0x010,
            ExecuteRead = 0x020,
            ExecuteReadWrite = 0x040,
            ExecuteWriteCopy = 0x080,
            Guard = 0x0100,
            NoCache = 0x0200,
            WriteCombine = 0x0400
        }
        
        [Flags]
        internal enum ProcessInformationClass
        {
            ProcessBasicInformation = 0x00,
            ProcessWow64Information = 0x1A
        }
        
        [Flags]
        internal enum SnapshotFlags
        {
            Module = 0x08,
            Module32 = 0x010
        }
        
        [Flags]
        internal enum ThreadAccess
        {
            SuspendResume = 0x02,
            GetContext = 0x08,
            SetContext = 0x010,
            AllAccess = SuspendResume | GetContext | SetContext
        }
        
        #endregion
        
        #region Structures
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct Wow64Context
        {
            internal ContextFlags Flags;
            
            private readonly uint Dr0;
            private readonly uint Dr1;
            private readonly uint Dr2;
            private readonly uint Dr3;
            private readonly uint Dr6;
            private readonly uint Dr7;
            
            private readonly Wow64FloatingSaveArea FloatingSave;
            
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
            internal uint Eip;
            private readonly uint SegCs;
            private readonly uint EFlags;
            private readonly uint Esp;
            private readonly uint SegSs;
            
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            private readonly byte[] ExtendedRegisters;
        }
                
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        internal struct Context
        {
            private readonly ulong P1Home;
            private readonly ulong P2Home;
            private readonly ulong P3Home;
            private readonly ulong P4Home;
            private readonly ulong P5Home;
            private readonly ulong P6Home;
            
            internal ContextFlags Flags;
            private readonly uint MxCsr;
            
            private readonly ushort SegCs;
            private readonly ushort SegDs;
            private readonly ushort SegEs;
            private readonly ushort SegFs;
            private readonly ushort SegGs;
            private readonly ushort SegSs;
            
            private readonly uint EFlags;
            
            private readonly ulong Dr0;
            private readonly ulong Dr1;
            private readonly ulong Dr2;
            private readonly ulong Dr3;
            private readonly ulong Dr6;
            private readonly ulong Dr7;
            
            private readonly ulong Rax;
            private readonly ulong Rcx;
            private readonly ulong Rdx;
            private readonly ulong Rbx;
            private readonly ulong Rsp;
            private readonly ulong Rbp;
            private readonly ulong Rsi;
            private readonly ulong Rdi;
            private readonly ulong R8;
            private readonly ulong R9;
            private readonly ulong R10;
            private readonly ulong R11;
            private readonly ulong R12;
            private readonly ulong R13;
            private readonly ulong R14;
            private readonly ulong R15;
            internal ulong Rip;
            
            private readonly SaveFormat DummyUnionName;
            
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            private readonly M128A[] VectorRegister;
            private readonly ulong VectorControl;
            
            private readonly ulong DebugControl;
            private readonly ulong LastBranchToRip;
            private readonly ulong LastBranchFromRip;
            private readonly ulong LastExceptionToRip;
            private readonly ulong LastExceptionFromRip;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        private struct Wow64FloatingSaveArea
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
        internal struct LdrDataTableEntry
        {
            internal readonly ListEntry InLoadOrderLinks;
            internal readonly ListEntry InMemoryOrderLinks;
            internal readonly ListEntry InInitOrderLinks;
            
            private readonly uint DllBase;
            
            private readonly uint EntryPoint;
            
            private readonly uint SizeOfImage;
            
            internal UnicodeString FullDllName;
            
            internal UnicodeString BaseDllName;
            
            private readonly uint Flags;
            
            private readonly ushort LoadCount;
            
            private readonly ushort TlsIndex;
            
            private readonly ListEntry HashTableEntry;
            
            private readonly ulong TimeDateStamp;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct LdrDataTableEntry64
        {
            internal readonly ListEntry64 InLoadOrderLinks;
            internal readonly ListEntry64 InMemoryOrderLinks;
            internal readonly ListEntry64 InInitOrderLinks;
            
            private readonly ulong DllBase;
            
            private readonly ulong EntryPoint;
            
            private readonly ulong SizeOfImage;
            
            internal UnicodeString64 FullDllName;
            
            internal UnicodeString64 BaseDllName;
            
            private readonly uint Flags;
            
            private readonly ushort LoadCount;
            
            private readonly ushort TlsIndex;
            
            private readonly ListEntry64 HashTableEntry;
            
            private readonly ulong TimeDateStamp;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct ListEntry
        {
            internal uint Flink;

            internal uint Blink;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct ListEntry64
        {
            internal ulong Flink;
            
            internal ulong Blink;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        private struct M128A
        {
            private readonly ulong High;
            private readonly ulong Low;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct MemoryBasicInformation
        {
            private readonly IntPtr BaseAddress;
            
            private readonly IntPtr AllocationBase;
            private readonly uint AllocationProtect;
            
            internal readonly IntPtr RegionSize;
            
            private readonly uint State;
            private readonly uint Protect;
            private readonly uint Type;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct ModuleEntry
        {
            internal uint Size;
                        
            private readonly uint ModuleId;
            private readonly uint ProcessId;
            
            private readonly uint UnusedValue1;
            private readonly uint UnusedValue2;
            
            internal IntPtr BaseAddress;
            
            private readonly uint BaseSize;
            
            private readonly IntPtr ModuleHandle;
            
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            internal readonly string Module;
            
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            internal readonly string ExePath;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct Peb
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            private readonly byte[] Reserved1;
            
            private readonly byte BeingDebugged;
            
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            private readonly byte[] Reserved2;
            
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            private readonly uint[] Reserved3;
            
            internal readonly uint Ldr;
            
            private readonly uint ProcessParameters;
            
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            private readonly uint[] Reserved4;
            
            private readonly uint AtlThunkSListPtr;
            
            private readonly uint Reserved5;
            
            private readonly ulong Reserved6;
            
            private readonly uint Reserved7;
            
            private readonly ulong Reserved8;
            
            private readonly ulong AtlThunkSListPtr32;
            
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 45)]
            private readonly uint[] Reserved9;
            
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            private readonly byte[] Reserved10;
            
            private readonly uint PostProcessInitRoutine;
            
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
            private readonly byte[] Reserved11;
            
            private readonly uint Reserved12;
            
            private readonly ulong SessionId;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct Peb64
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            private readonly byte[] Reserved1;
            
            private readonly byte BeingDebugged;
            
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 21)]
            private readonly byte[] Reserved2;
            
            internal readonly ulong Ldr;
            
            private readonly ulong ProcessParameters;
            
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 520)]
            private readonly byte[] Reserved3;
            
            private readonly ulong PostProcessInitRoutine;
            
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 136)]
            private readonly byte[] Reserved4;
            
            private readonly ulong SessionId;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct PebLdrData
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            private readonly byte[] Reserved1;
            
            private readonly uint Reserved2;
            
            internal readonly ListEntry InLoadOrderModuleList;
            private readonly ListEntry InMemoryOrderModuleList;
            private readonly ListEntry InInitOrderModuleList;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct PebLdrData64
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            private readonly byte[] Reserved1;
            
            private readonly ulong Reserved2;
            
            internal readonly ListEntry64 InLoadOrderModuleList;
            private readonly ListEntry64 InMemoryOrderModuleList;
            private readonly ListEntry64 InInitOrderModuleList;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct ProcessBasicInformation
        {
            private readonly IntPtr ExitStatus;
            
            internal readonly IntPtr PebBaseAddress;
            
            private readonly IntPtr AffinityMask;
            
            private readonly IntPtr BasePriority;
            
            private readonly IntPtr UniqueProcessId;
            private readonly IntPtr InheritedFromUniqueProcessId;
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
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct UnicodeString
        {
            internal readonly ushort Length;
            
            internal readonly ushort MaxLength;
            
            internal readonly uint Buffer;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct UnicodeString64
        {
            internal readonly ushort Length;
            
            internal readonly ushort MaxLength;
            
            internal readonly ulong Buffer;
        }
        
        #endregion
    }
}