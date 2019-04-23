using Bleak.Handlers;
using Bleak.Injection.Interfaces;
using Bleak.Injection.Methods.Shellcode;
using Bleak.Injection.Objects;
using Bleak.Memory;
using Bleak.Native;
using Bleak.Native.SafeHandle;
using Bleak.Syscall.Definitions;
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Bleak.Injection.Methods
{
    internal class ThreadHijack : IInjectionMethod
    {
        public bool Call(InjectionProperties injectionProperties)
        {
            // Get the address of the LoadLibraryW function in the target process

            var loadLibraryAddress = injectionProperties.RemoteProcess.GetFunctionAddress("kernel32.dll", "LoadLibraryW");

            // Write the DLL path into the target process

            var dllPathBuffer = injectionProperties.MemoryManager.AllocateVirtualMemory(IntPtr.Zero, injectionProperties.DllPath.Length, Enumerations.MemoryProtectionType.ExecuteReadWrite);

            var dllPathBytes = Encoding.Unicode.GetBytes(injectionProperties.DllPath);

            injectionProperties.MemoryManager.WriteVirtualMemory(dllPathBuffer, dllPathBytes);

            // Open a handle to the first thread in the target process

            var threadHandle = (SafeThreadHandle) injectionProperties.SyscallManager.InvokeSyscall<NtOpenThread>(injectionProperties.RemoteProcess.TargetProcess.Threads[0].Id);

            if (injectionProperties.RemoteProcess.IsWow64)
            {
                // Suspend the thread

                if (PInvoke.Wow64SuspendThread(threadHandle) == -1)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to suspend a thread in the target process");
                }

                // Get the context of the thread

                var threadContextBuffer = LocalMemoryTools.StoreStructureInBuffer(new Structures.Wow64Context { ContextFlags = Enumerations.ContextFlags.Control });

                if (PInvoke.Wow64GetThreadContext(threadHandle, threadContextBuffer) == 0)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to get the context of a thread in the target process");
                }

                var threadContext = Marshal.PtrToStructure<Structures.Wow64Context>(threadContextBuffer);

                LocalMemoryTools.FreeMemoryForBuffer(threadContextBuffer);

                // Write the shellcode used to call LoadLibraryW from the thread into the target process

                var shellcode = ThreadHijackX86.GetShellcode((IntPtr) threadContext.Eip, dllPathBuffer, loadLibraryAddress);

                var shellcodeBuffer = injectionProperties.MemoryManager.AllocateVirtualMemory(IntPtr.Zero, shellcode.Length, Enumerations.MemoryProtectionType.ExecuteReadWrite);

                injectionProperties.MemoryManager.WriteVirtualMemory(shellcodeBuffer, shellcode);

                // Overwrite the instruction pointer of the thread with the address of the shellcode buffer

                threadContext.Eip = (uint) shellcodeBuffer;

                threadContextBuffer = LocalMemoryTools.StoreStructureInBuffer(threadContext);

                // Update the context of the thread

                if (PInvoke.Wow64SetThreadContext(threadHandle, threadContextBuffer) == 0)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to set the context of a thread in the target process");
                }

                LocalMemoryTools.FreeMemoryForBuffer(threadContextBuffer);
            }

            else
            {
                // Suspend the thread

                injectionProperties.SyscallManager.InvokeSyscall<NtSuspendThread>(threadHandle);

                // Get the context of the thread

                var threadContextBuffer = (IntPtr) injectionProperties.SyscallManager.InvokeSyscall<NtGetContextThread>(threadHandle);

                var threadContext = Marshal.PtrToStructure<Structures.Context>(threadContextBuffer);

                LocalMemoryTools.FreeMemoryForBuffer(threadContextBuffer);

                // Write the shellcode used to call LoadLibraryW from the thread into the target process

                var shellcode = ThreadHijackX64.GetShellcode((IntPtr) threadContext.Rip, dllPathBuffer, loadLibraryAddress);

                var shellcodeBuffer = injectionProperties.MemoryManager.AllocateVirtualMemory(IntPtr.Zero, shellcode.Length, Enumerations.MemoryProtectionType.ExecuteReadWrite);

                injectionProperties.MemoryManager.WriteVirtualMemory(shellcodeBuffer, shellcode);

                // Overwrite the instruction pointer of the thread with the address of the shellcode buffer

                threadContext.Rip = (ulong) shellcodeBuffer;

                threadContextBuffer = LocalMemoryTools.StoreStructureInBuffer(threadContext);

                // Update the context of the thread

                injectionProperties.SyscallManager.InvokeSyscall<NtSetContextThread>(threadHandle, threadContextBuffer);

                LocalMemoryTools.FreeMemoryForBuffer(threadContextBuffer);
            }

            // Resume the thread

            injectionProperties.SyscallManager.InvokeSyscall<NtResumeThread>(threadHandle);

            PInvoke.SwitchToThisWindow(injectionProperties.RemoteProcess.TargetProcess.MainWindowHandle, true);

            threadHandle.Dispose();

            return true;
        }
    }
}
