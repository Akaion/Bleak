using Bleak.Handlers;
using Bleak.Methods.Shellcode;
using Bleak.Native;
using Bleak.SafeHandle;
using Bleak.Syscall.Definitions;
using Bleak.Tools;
using Bleak.Wrappers;
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Bleak.Methods
{
    internal class SetThreadContext
    {
        private readonly PropertyWrapper _propertyWrapper;

        internal SetThreadContext(PropertyWrapper propertyWrapper)
        {
            _propertyWrapper = propertyWrapper;
        }

        internal bool Call()
        {
            // Get the address of the LoadLibraryW function

            var loadLibraryAddress = _propertyWrapper.TargetProcess.GetFunctionAddress("kernel32.dll", "LoadLibraryW");

            // Write the DLL path into the target process

            var dllPathBuffer = _propertyWrapper.MemoryManager.AllocateVirtualMemory(_propertyWrapper.DllPath.Length, Enumerations.MemoryProtectionType.ExecuteReadWrite);

            var dllPathBytes = Encoding.Unicode.GetBytes(_propertyWrapper.DllPath + "\0");

            _propertyWrapper.MemoryManager.WriteVirtualMemory(dllPathBuffer, dllPathBytes);

            // Open a handle to the first thread in the target process

            var threadHandle = (SafeThreadHandle) _propertyWrapper.SyscallManager.InvokeSyscall<NtOpenThread>(_propertyWrapper.TargetProcess.Process.Threads[0].Id);

            if (_propertyWrapper.TargetProcess.IsWow64)
            {
                // Suspend the thread

                if (PInvoke.Wow64SuspendThread(threadHandle) == -1)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to suspend a thread in the target process");
                }

                // Get the context of the thread

                var threadContextBuffer = MemoryTools.StoreStructureInBuffer(new Structures.Wow64Context { ContextFlags = Enumerations.ContextFlags.Control });

                if (PInvoke.Wow64GetThreadContext(threadHandle, threadContextBuffer) == 0)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to get the context of a thread in the target process");
                }
                
                var threadContext = Marshal.PtrToStructure<Structures.Wow64Context>(threadContextBuffer);

                // Write the shellcode used to call LoadLibraryW from the thread into the target process

                var shellcode = ThreadHijackX86.GetShellcode((IntPtr) threadContext.Eip, dllPathBuffer, loadLibraryAddress);

                var shellcodeBuffer = _propertyWrapper.MemoryManager.AllocateVirtualMemory(shellcode.Length, Enumerations.MemoryProtectionType.ExecuteReadWrite);

                _propertyWrapper.MemoryManager.WriteVirtualMemory(shellcodeBuffer, shellcode);

                // Overwrite the instruction pointer of the thread with the shellcode buffer

                threadContext.Eip = (uint) shellcodeBuffer;

                // Set the context of the thread

                threadContextBuffer = MemoryTools.StoreStructureInBuffer(threadContext);

                if(PInvoke.Wow64SetThreadContext(threadHandle, threadContextBuffer) == 0)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to set the context of a thread in the target process");
                }

                MemoryTools.FreeMemoryForBuffer(threadContextBuffer);
            }

            else
            {
                // Suspend the thread

                _propertyWrapper.SyscallManager.InvokeSyscall<NtSuspendThread>(threadHandle);

                // Get the context of the thread

                var threadContextBuffer = (IntPtr) _propertyWrapper.SyscallManager.InvokeSyscall<NtGetContextThread>(threadHandle);

                var threadContext = Marshal.PtrToStructure<Structures.Context>(threadContextBuffer);

                // Write the shellcode used to call LoadLibraryW from the thread into the target process

                var shellcode = ThreadHijackX64.GetShellcode((IntPtr) threadContext.Rip, dllPathBuffer, loadLibraryAddress);

                var shellcodeBuffer = _propertyWrapper.MemoryManager.AllocateVirtualMemory(shellcode.Length, Enumerations.MemoryProtectionType.ExecuteReadWrite);

                _propertyWrapper.MemoryManager.WriteVirtualMemory(shellcodeBuffer, shellcode);

                // Overwrite the instruction pointer of the thread with the shellcode buffer

                threadContext.Rip = (ulong) shellcodeBuffer;

                // Set the context of the thread

                threadContextBuffer = MemoryTools.StoreStructureInBuffer(threadContext);

                _propertyWrapper.SyscallManager.InvokeSyscall<NtSetThreadContext>(threadHandle, threadContextBuffer);

                MemoryTools.FreeMemoryForBuffer(threadContextBuffer);
            }

            // Resume the thread

            _propertyWrapper.SyscallManager.InvokeSyscall<NtResumeThread>(threadHandle);

            PInvoke.SwitchToThisWindow(_propertyWrapper.TargetProcess.Process.MainWindowHandle, true);

            threadHandle.Dispose();

            return true;
        }
    }
}
