using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Bleak.Handlers;
using Bleak.Injection.Interfaces;
using Bleak.Injection.Objects;
using Bleak.Native;

namespace Bleak.Injection.Methods
{
    internal class HijackThread : IInjectionMethod
    {
        private readonly InjectionWrapper _injectionWrapper;

        public HijackThread(InjectionWrapper injectionWrapper)
        {
            _injectionWrapper = injectionWrapper;
        }

        public IntPtr Call()
        {
            // Write the DLL path into the remote process

            var dllPathBuffer = _injectionWrapper.MemoryManager.AllocateVirtualMemory(_injectionWrapper.DllPath.Length);

            var dllPathBytes = Encoding.Unicode.GetBytes(_injectionWrapper.DllPath);

            _injectionWrapper.MemoryManager.WriteVirtualMemory(dllPathBuffer, dllPathBytes);

            // Write a UnicodeString representing the DLL path into the remote process

            IntPtr unicodeStringBuffer;

            if (_injectionWrapper.RemoteProcess.IsWow64)
            {
                var unicodeString = new Structures.UnicodeString32(_injectionWrapper.DllPath)
                {
                    Buffer = (uint) dllPathBuffer
                };

                unicodeStringBuffer = _injectionWrapper.MemoryManager.AllocateVirtualMemory<Structures.UnicodeString32>();

                _injectionWrapper.MemoryManager.WriteVirtualMemory(unicodeStringBuffer, unicodeString);
            }

            else
            {
                var unicodeString = new Structures.UnicodeString64(_injectionWrapper.DllPath)
                {
                    Buffer = (ulong) dllPathBuffer
                };

                unicodeStringBuffer = _injectionWrapper.MemoryManager.AllocateVirtualMemory<Structures.UnicodeString64>();

                _injectionWrapper.MemoryManager.WriteVirtualMemory(unicodeStringBuffer, unicodeString);
            }

            // Get the address of the LdrLoadDll function in the remote process

            var ldrLoadDllAddress = _injectionWrapper.RemoteProcess.GetFunctionAddress("ntdll.dll", "LdrLoadDll");

            var returnBuffer = _injectionWrapper.MemoryManager.AllocateVirtualMemory<uint>();

            var moduleHandleBuffer = _injectionWrapper.MemoryManager.AllocateVirtualMemory<IntPtr>();

            // Write the shellcode used to call LdrLoadDll from a thread into the remote process

            var shellcode = _injectionWrapper.Assembler.AssembleThreadFunctionCall(CallingConvention.StdCall, ldrLoadDllAddress, returnBuffer, 0, 0, (ulong) unicodeStringBuffer, (ulong) moduleHandleBuffer);

            var shellcodeBuffer = _injectionWrapper.MemoryManager.AllocateVirtualMemory(shellcode.Length);

            _injectionWrapper.MemoryManager.WriteVirtualMemory(shellcodeBuffer, shellcode);

            // Open a handle to the first thread in the remote process

            var firstThreadHandle = PInvoke.OpenThread(Enumerations.ThreadAccessMask.AllAccess, false, _injectionWrapper.RemoteProcess.Process.Threads[0].Id);

            if (_injectionWrapper.RemoteProcess.IsWow64)
            {
                // Suspend the thread

                if (PInvoke.Wow64SuspendThread(firstThreadHandle) == -1)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to suspend a thread in the remote process");
                }

                var threadContextBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<Structures.Wow64Context>());

                Marshal.StructureToPtr(new Structures.Wow64Context { ContextFlags = Enumerations.ContextFlags.Control }, threadContextBuffer, false);

                // Get the context of the thread

                if (!PInvoke.Wow64GetThreadContext(firstThreadHandle, threadContextBuffer))
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to get the context of a thread in the remote process");
                }

                var threadContext = Marshal.PtrToStructure<Structures.Wow64Context>(threadContextBuffer);

                // Write the original instruction pointer of the thread into the top of its stack

                threadContext.Esp -= sizeof(uint);

                _injectionWrapper.MemoryManager.WriteVirtualMemory((IntPtr) threadContext.Esp, threadContext.Eip);

                // Overwrite the instruction pointer of the thread with the address of the shellcode buffer

                threadContext.Eip = (uint) shellcodeBuffer;

                Marshal.StructureToPtr(threadContext, threadContextBuffer, true);

                // Update the context of the thread

                if (!PInvoke.Wow64SetThreadContext(firstThreadHandle, threadContextBuffer))
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to set the context of a thread in the remote process");
                }
            }

            else
            {
                // Suspend the thread

                if (PInvoke.SuspendThread(firstThreadHandle) == -1)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to suspend a thread in the remote process");
                }

                var threadContextBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<Structures.Context>());

                Marshal.StructureToPtr(new Structures.Context { ContextFlags = Enumerations.ContextFlags.Control }, threadContextBuffer, false);

                // Get the context of the thread

                if (!PInvoke.GetThreadContext(firstThreadHandle, threadContextBuffer))
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to get the context of a thread in the remote process");
                }

                var threadContext = Marshal.PtrToStructure<Structures.Context>(threadContextBuffer);

                // Write the original instruction pointer of the thread into the top of its stack

                threadContext.Rsp -= sizeof(ulong);

                _injectionWrapper.MemoryManager.WriteVirtualMemory((IntPtr) threadContext.Rsp, threadContext.Rip);

                // Overwrite the instruction pointer of the thread with the address of the shellcode buffer

                threadContext.Rip = (ulong) shellcodeBuffer;

                Marshal.StructureToPtr(threadContext, threadContextBuffer, true);

                // Update the context of the thread

                if (!PInvoke.SetThreadContext(firstThreadHandle, threadContextBuffer))
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to set the context of a thread in the remote process");
                }
            }

            // Flush the instruction cache of the remote process to ensure all memory operations have been completed

            if (!PInvoke.FlushInstructionCache(Process.GetCurrentProcess().SafeHandle, IntPtr.Zero, 0))
            {
                ExceptionHandler.ThrowWin32Exception("Failed to flush the instruction cache of the remote process");
            }

            // Resume the thread

            if (PInvoke.ResumeThread(firstThreadHandle) == -1)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to resume a thread in the remote process");
            }

            firstThreadHandle.Dispose();

            // Send a message to the thread to ensure it resumes

            PInvoke.PostThreadMessage(_injectionWrapper.RemoteProcess.Process.Threads[0].Id, Enumerations.WindowsMessage.Keydown, Enumerations.VirtualKey.LeftButton, IntPtr.Zero);

            // Read the returned value of LdrLoadDll from the buffer

            var ntStatus = (Enumerations.NtStatus) _injectionWrapper.MemoryManager.ReadVirtualMemory<uint>(returnBuffer);

            if (ntStatus != Enumerations.NtStatus.Success)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to call LdrLoadDll in the remote process", ntStatus);
            }

            while (_injectionWrapper.RemoteProcess.Modules.All(module => module.FilePath != _injectionWrapper.DllPath))
            {
                _injectionWrapper.RemoteProcess.Refresh();
            }

            _injectionWrapper.MemoryManager.FreeVirtualMemory(dllPathBuffer);

            _injectionWrapper.MemoryManager.FreeVirtualMemory(unicodeStringBuffer);

            try
            {
                // Read the base address of the DLL that was loaded in the remote process

                return _injectionWrapper.MemoryManager.ReadVirtualMemory<IntPtr>(moduleHandleBuffer);
            }

            finally
            {
                _injectionWrapper.MemoryManager.FreeVirtualMemory(moduleHandleBuffer);
            }
        }
    }
}