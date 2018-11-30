using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using static Bleak.Etc.Native;
using static Bleak.Etc.Shellcode;
using static Bleak.Etc.Wrapper;

namespace Bleak.Methods
{
     internal static class SetThreadContext
    {
        internal static bool Inject(string dllPath, string processName)
        {
            // Ensure both parameters are valid

            if (string.IsNullOrEmpty(dllPath) || string.IsNullOrEmpty(processName))
            {
                return false;
            }

            // Ensure the dll exists

            if (!File.Exists(dllPath))
            {
                return false;
            }

            // Get an instance of the specified process

            Process process;

            try
            {
                process = Process.GetProcessesByName(processName)[0];
            }

            catch (IndexOutOfRangeException)
            {
                return false;
            }

            // Inject the dll

            return Inject(dllPath, process);
        }

        internal static bool Inject(string dllPath, int processId)
        {
            // Ensure both parameters are valid

            if (string.IsNullOrEmpty(dllPath) || processId == 0)
            {
                return false;
            }

            // Ensure the dll exists

            if (!File.Exists(dllPath))
            {
                return false;
            }

            // Get an instance of the specified process

            Process process;

            try
            {
                process = Process.GetProcessById(processId);
            }

            catch (IndexOutOfRangeException)
            {
                return false;
            }

            // Inject the dll

            return Inject(dllPath, process);
        }

        private static bool Inject(string dllPath, Process process)
        {
            // Determine whether compiled as x86 or x64

            var compiledAsx64 = Environment.Is64BitProcess;

            // Get the address of the load library method

            var loadLibraryAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryW");

            if (loadLibraryAddress == IntPtr.Zero)
            {
                return false;
            }

            // Get a handle to the specified process

            var processHandle = process.SafeHandle;

            if (processHandle == null)
            {
                return false;
            }

            // Allocate memory for the dll name

            var dllNameSize = dllPath.Length;

            var dllNameAddress = VirtualAllocEx(processHandle, IntPtr.Zero, dllNameSize, MemoryAllocation.Commit | MemoryAllocation.Reserve, MemoryProtection.PageExecuteReadWrite);

            if (dllNameAddress == IntPtr.Zero)
            {
                return false;
            }

            // Write the dll name into memory

            var dllNameBytes = Encoding.Unicode.GetBytes(dllPath + "\0");

            if (!WriteMemory(processHandle, dllNameAddress, dllNameBytes))
            {
                return false;
            }

            // Allocate memory for the shellcode

            var shellcodeSize = compiledAsx64 ? 87 : 22;

            var shellcodeAddress = VirtualAllocEx(processHandle, IntPtr.Zero, shellcodeSize, MemoryAllocation.Commit | MemoryAllocation.Reserve, MemoryProtection.PageExecuteReadWrite);

            // Get the handle of the first thread in the specified process

            var threadId = process.Threads[0].Id;

            // Open a handle to the thread

            var threadHandle = OpenThread(ThreadAccess.SuspendResume | ThreadAccess.GetContext | ThreadAccess.SetContext, false, threadId);

            if (threadHandle == IntPtr.Zero)
            {
                return false;
            }

            // Suspend the thread

            SuspendThread(threadHandle);

            // If compiled as x86

            if (!compiledAsx64)
            {
                // Get the threads context

                var context = new Context { Flags = ContextFlags.ContextControl };

                if (!GetThreadContext(threadHandle, ref context))
                {    
                    return false;
                }

                // Save the instruction pointer

                var instructionPointer = context.Eip;

                // Change the instruction pointer to the shellcode pointer

                context.Eip = shellcodeAddress;

                // Write the shellcode into memory

                var shellcode = CallLoadLibraryx86(instructionPointer, dllNameAddress, loadLibraryAddress);

                if (!WriteMemory(processHandle, shellcodeAddress, shellcode))
                {
                    return false;
                }

                // Set the threads context

                if (!SetThreadContext(threadHandle, ref context))
                {
                    return false;
                }
            }

            // If compiled as x64

            else
            {
                // Get the threads context

                var context = new Context64 { Flags = ContextFlags.ContextControl };

                if (!GetThreadContext(threadHandle, ref context))
                {
                    return false;
                }

                // Save the instruction pointer

                var instructionPointer = context.Rip;

                // Change the instruction pointer to the shellcode pointer

                context.Rip = shellcodeAddress;

                // Write the shellcode into memory

                var shellcode = CallLoadLibraryx64(instructionPointer, dllNameAddress, loadLibraryAddress);

                if (!WriteMemory(processHandle, shellcodeAddress, shellcode))
                {
                    return false;
                }

                // Set the threads context

                if (!SetThreadContext(threadHandle, ref context))
                {
                    return false;
                }
            }

            // Resume the thread

            ResumeThread(threadHandle);

            // Simulate a keypress to execute the dll

            PostMessage(process.MainWindowHandle, WindowsMessage.WmKeydown, IntPtr.Zero, IntPtr.Zero);

            // Free the previously allocated memory

            VirtualFreeEx(processHandle, dllNameAddress, dllNameSize, MemoryAllocation.Release);

            VirtualFreeEx(processHandle, shellcodeAddress, shellcodeSize, MemoryAllocation.Release);

            // Close the previously opened handle

            CloseHandle(threadHandle);

            return true;
        }
    }
}