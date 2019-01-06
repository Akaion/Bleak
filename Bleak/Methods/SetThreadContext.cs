using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Bleak.Etc;
using Jupiter;
using static Bleak.Etc.Native;

namespace Bleak.Methods
{
    internal class SetThreadContext
    {
        private readonly MemoryModule _memoryModule;

        internal SetThreadContext()
        {
            _memoryModule = new MemoryModule();
        }
        
        internal bool Inject(Process process, string dllPath)
        {
            // Ensure the process has kernel32.dll loaded

            if (LoadLibrary("kernel32.dll") is null)
            {
                return false;
            }
            
            // Get the id of the process

            var processId = process.Id;
            
            // Get the address of the LoadLibraryW method from kernel32.dll
            
            var loadLibraryAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryW");
            
            if (loadLibraryAddress == IntPtr.Zero)
            {
                return false;
            }
            
            // Allocate memory for the dll path in the process
            
            var dllPathSize = dllPath.Length;

            var dllPathAddress = _memoryModule.AllocateMemory(processId, dllPathSize);

            if (dllPathAddress == IntPtr.Zero)
            {
                return false;
            }
            
            // Write the dll path into the process
            
            var dllPathBytes = Encoding.Unicode.GetBytes(dllPath + "\0");

            if (!_memoryModule.WriteMemory(processId, dllPathAddress, dllPathBytes))
            {
                return false;
            }
            
            // Open a handle to the process
            
            var processHandle = process.SafeHandle;
            
            // Determine if the process is running under WOW64

            IsWow64Process(processHandle, out var isWow64);
            
            // Allocate memory for the shellcode in the process

            var shellcodeSize = isWow64 ? 22 : 87;

            var shellcodeAddress = _memoryModule.AllocateMemory(processId, shellcodeSize);

            if (shellcodeAddress == IntPtr.Zero)
            {
                return false;
            }
            
            // Get the id of the first thread in the process

            var threadId = process.Threads[0].Id;
            
            // Open a handle to the thread

            var threadHandle = OpenThread(ThreadAccess.AllAccess, false, threadId);

            if (threadHandle is null)
            {
                return false;
            }
            
            // Suspend the thread

            if (SuspendThread(threadHandle) == -1)
            {
                return false;
            }
            
            // If the process is x86
            
            if (isWow64)
            {
                var threadContext = new Context {Flags = ContextFlags.ContextControl};
                
                // Get the size of the structure
                
                var threadContextSize = Marshal.SizeOf(threadContext);

                // Allocate memory for a buffer to store the structure
                
                var buffer = Marshal.AllocHGlobal(threadContextSize);
                
                // Convert the structure to bytes
                
                var threadContextBytes = Tools.StructureToBytes(threadContext);
                
                // Copy the structure bytes into the buffer
                
                Marshal.Copy(threadContextBytes, 0, buffer, threadContextSize);
                
                // Get the context of the thread and save it in the buffer
                
                if (!GetThreadContext(threadHandle, buffer))
                {    
                    return false;
                }
                
                // Read the new thread context structure from the buffer
                
                threadContext = Tools.PointerToStructure<Context>(buffer);
                
                // Save the instruction pointer

                var instructionPointer = threadContext.Eip;
                
                // Write the shellcode into the memory of the process

                var shellcode = Shellcode.CallLoadLibraryx86(instructionPointer, dllPathAddress, loadLibraryAddress);

                if (!_memoryModule.WriteMemory(processId, shellcodeAddress, shellcode))
                {
                    return false;
                }
                
                // Change the instruction pointer to the shellcode address

                threadContext.Eip = shellcodeAddress;
                
                // Convert the structure to bytes
                
                threadContextBytes = Tools.StructureToBytes(threadContext);
                
                // Copy the structure bytes into the buffer
                
                Marshal.Copy(threadContextBytes, 0, buffer, threadContextSize);
                
                // Set the context of the thread with the new context

                if (!SetThreadContext(threadHandle, buffer))
                {
                    return false;
                }
                
                // Free the memory previously allocated for the buffer
                
                Marshal.FreeHGlobal(buffer);
            }

            // If the process is x64
            
            else
            {   
                var threadContext = new Context64 {Flags = ContextFlags.ContextControl};

                // Get the size of the structure
                
                var threadContextSize = Marshal.SizeOf(threadContext);
                
                // Allocate memory for a buffer to store the structure
                
                var buffer = Marshal.AllocHGlobal(threadContextSize);

                // Convert the structure to bytes
                
                var threadContextBytes = Tools.StructureToBytes(threadContext);
                
                // Copy the structure bytes into the buffer
                
                Marshal.Copy(threadContextBytes, 0, buffer, threadContextSize);
                
                // Get the context of the thread and save it in the buffer
                
                if (!GetThreadContext(threadHandle, buffer))
                {    
                    return false;
                }

                // Read the new thread context structure from the buffer
                
                threadContext = Tools.PointerToStructure<Context64>(buffer);
                
                // Save the instruction pointer

                var instructionPointer = threadContext.Rip;

                // Write the shellcode into the memory of the process

                var shellcode = Shellcode.CallLoadLibraryx64(instructionPointer, dllPathAddress, loadLibraryAddress);

                if (!_memoryModule.WriteMemory(processId, shellcodeAddress, shellcode))
                {
                    return false;
                }
                
                // Change the instruction pointer to the shellcode address

                threadContext.Rip = shellcodeAddress;

                // Convert the structure to bytes
                
                threadContextBytes = Tools.StructureToBytes(threadContext);
                
                // Copy the structure bytes into the buffer
                
                Marshal.Copy(threadContextBytes, 0, buffer, threadContextSize);
                
                // Set the context of the thread with the new context

                if (!SetThreadContext(threadHandle, buffer))
                {
                    return false;
                }
                
                // Free the memory previously allocated for the buffer
                
                Marshal.FreeHGlobal(buffer);
            }
            
            // Resume the suspended thread

            if (ResumeThread(threadHandle) == -1)
            {
                return false;
            }
            
            // Open a handle to the main window handle of the process
            
            var windowHandle = new SafeWindowHandle(process.MainWindowHandle);
            
            // Switch to the process to load the dll
            
            SwitchToThisWindow(windowHandle, true);

            // Buffer the execution by 10 milliseconds to avoid freeing memory before it has been referenced
            
            Tools.AsyncWait(10);
            
            // Free the memory previously allocated for the dll path
            
            if (!_memoryModule.FreeMemory(processId, dllPathAddress))
            {
                return false;
            }
            
            // Free the memory previously allocated for the shellcode
            
            if (!_memoryModule.FreeMemory(processId, shellcodeAddress))
            {
                return false;
            }
            
            // Close the handle opened to the process
            
            process.Close();
            
            // Close the handle opened to the thread
            
            threadHandle.Close();
            
            return true;
        }
    }
}