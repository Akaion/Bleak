using Bleak.Handlers;
using Bleak.Methods.Interfaces;
using Bleak.Methods.Shellcode;
using Bleak.Native;
using Bleak.SafeHandle;
using Bleak.Tools;
using Bleak.Wrappers;
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Bleak.Methods
{
    internal class SetThreadContext : IInjectionMethod
    {
        private readonly PropertyWrapper PropertyWrapper;

        internal SetThreadContext(PropertyWrapper propertyWrapper)
        {
            PropertyWrapper = propertyWrapper;
        }

        public bool Call()
        {
            // Get the address of LoadLibraryW in the target process

            var loadLibraryAddress = NativeTools.GetFunctionAddress(PropertyWrapper, "kernel32.dll", "LoadLibraryW");

            // Allocate a buffer for the DLL path in the target process

            var dllPathBuffer = PropertyWrapper.MemoryManager.Value.AllocateMemory(PropertyWrapper.DllPath.Length, Enumerations.MemoryProtectionType.ExecuteReadWrite);

            // Write the DLL path into the buffer

            var dllPathBytes = Encoding.Unicode.GetBytes(PropertyWrapper.DllPath + "\0");

            PropertyWrapper.MemoryManager.Value.WriteMemory(dllPathBuffer, dllPathBytes);

            // Open a handle to the first thread in the target process

            var threadHandle = (SafeThreadHandle) PropertyWrapper.SyscallManager.InvokeSyscall<Syscall.Definitions.NtOpenThread>(PropertyWrapper.Process.Threads[0].Id);

            IntPtr shellcodeBuffer;

            if (PropertyWrapper.IsWow64Process.Value)
            {
                // Suspend the thread in the target process

                if (PInvoke.Wow64SuspendThread(threadHandle) == -1)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to suspend a thread in the target process");
                }

                // Get the context of the thread in the target process

                var threadContextBuffer = MemoryTools.StoreStructureInBuffer(new Structures.Wow64Context { ContextFlags = Enumerations.ContextFlags.Control });

                if (PInvoke.Wow64GetThreadContext(threadHandle, threadContextBuffer) == 0)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to get the context of a thread in the target process");
                }

                // Marshal the context from the buffer

                var threadContext = Marshal.PtrToStructure<Structures.Wow64Context>(threadContextBuffer);

                var instructionPointer = threadContext.Eip;

                // Create the shellcode used to call LoadLibraryW from the thread

                var shellcode = ThreadHijackX86.GetShellcode((IntPtr) instructionPointer, dllPathBuffer, loadLibraryAddress);

                // Store the shellcode in a buffer in the target process

                shellcodeBuffer = PropertyWrapper.MemoryManager.Value.AllocateMemory(shellcode.Length, Enumerations.MemoryProtectionType.ExecuteReadWrite);

                PropertyWrapper.MemoryManager.Value.WriteMemory(shellcodeBuffer, shellcode);

                // Change the instruction pointer of the thread to the address of the shellcode

                threadContext.Eip = (uint) shellcodeBuffer;

                // Update the context of the thread in the target process

                threadContextBuffer = MemoryTools.StoreStructureInBuffer(threadContext);

                if (PInvoke.Wow64SetThreadContext(threadHandle, threadContextBuffer) == 0)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to set the context of a thread in the target process");
                }

                // Free the memory allocated for the buffer

                MemoryTools.FreeMemoryForBuffer(threadContextBuffer, Marshal.SizeOf<Structures.Wow64Context>());
            }

            else
            {
                // Suspend the thread in the target process

                PropertyWrapper.SyscallManager.InvokeSyscall<Syscall.Definitions.NtSuspendThread>(threadHandle);

                // Get the context of the thread in the target process

                var threadContextBuffer = (IntPtr) PropertyWrapper.SyscallManager.InvokeSyscall<Syscall.Definitions.NtGetContextThread>(threadHandle);

                // Marshal the thread context from the buffer

                var threadContext = Marshal.PtrToStructure<Structures.Context>(threadContextBuffer);

                var instructionPointer = threadContext.Rip;

                // Create the shellcode used to call LoadLibraryW from the thread

                var shellcode = ThreadHijackX64.GetShellcode((IntPtr) instructionPointer, dllPathBuffer, loadLibraryAddress);

                // Store the shellcode in a buffer in the target process

                shellcodeBuffer = PropertyWrapper.MemoryManager.Value.AllocateMemory(shellcode.Length, Enumerations.MemoryProtectionType.ExecuteReadWrite);

                PropertyWrapper.MemoryManager.Value.WriteMemory(shellcodeBuffer, shellcode);

                // Change the instruction pointer of the thread to the address of the shellcode

                threadContext.Rip = (ulong) shellcodeBuffer;

                // Update the context of the thread in the target process

                threadContextBuffer = MemoryTools.StoreStructureInBuffer(threadContext);

                PropertyWrapper.SyscallManager.InvokeSyscall<Syscall.Definitions.NtSetContextThread>(threadHandle, threadContextBuffer);

                // Free the memory allocated for the buffer

                MemoryTools.FreeMemoryForBuffer(threadContextBuffer, Marshal.SizeOf<Structures.Context>());
            }

            // Resume the thread in the target process

            PropertyWrapper.SyscallManager.InvokeSyscall<Syscall.Definitions.NtResumeThread>(threadHandle);

            // Alt tab to the process to load the DLL

            PInvoke.SwitchToThisWindow(PropertyWrapper.Process.MainWindowHandle, true);

            // Buffer the execution by 10 milliseconds to avoid freeing memory before it has been referenced

            Thread.Sleep(10);

            // Free the memory allocated for the shellcode

            PropertyWrapper.MemoryManager.Value.FreeMemory(shellcodeBuffer);

            threadHandle.Dispose();

            return true;
        }
    }
}
