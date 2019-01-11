using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using Bleak.Etc;
using Bleak.Services;
using Jupiter;

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

            if (Native.LoadLibrary("kernel32.dll") is null)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to load kernel32.dll into the process");
            }
            
            // Get the id of the process

            var processId = process.Id;
            
            // Get the address of the LoadLibraryW method from kernel32.dll
            
            var loadLibraryAddress = Native.GetProcAddress(Native.GetModuleHandle("kernel32.dll"), "LoadLibraryW");
            
            if (loadLibraryAddress == IntPtr.Zero)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to find the address of the LoadLibraryW method in kernel32.dll");
            }
            
            // Allocate memory for the dll path in the process
            
            var dllPathSize = dllPath.Length;

            var dllPathAddress = IntPtr.Zero;

            try
            {
                dllPathAddress = _memoryModule.AllocateMemory(processId, dllPathSize);
            }

            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to allocate memory for the dll path in the process");
            }
            
            // Write the dll path into the process
            
            var dllPathBytes = Encoding.Unicode.GetBytes(dllPath + "\0");

            try
            {
                _memoryModule.WriteMemory(processId, dllPathAddress, dllPathBytes);
            }

            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to write the dll path into the memory of the process");   
            }
            
            // Open a handle to the process
            
            var processHandle = process.SafeHandle;
            
            // Determine if the process is running under WOW64

            Native.IsWow64Process(processHandle, out var isWow64);
            
            // Allocate memory for the shellcode in the process

            var shellcodeSize = isWow64 ? 22 : 87;

            var shellcodeAddress = IntPtr.Zero;

            try
            {
                shellcodeAddress = _memoryModule.AllocateMemory(processId, shellcodeSize);
            }

            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to allocate memory for the shellcode in the process");              
            }

            // Get the id of the first thread in the process

            var threadId = process.Threads[0].Id;
            
            // Open a handle to the thread

            var threadHandle = Native.OpenThread(Native.ThreadAccess.AllAccess, false, threadId);

            if (threadHandle is null)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to open a handle to the first thread in the process");
            }
            
            // Suspend the thread

            if (Native.SuspendThread(threadHandle) == -1)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to suspend the first thread in the process");
            }
            
            // If the process is x86
            
            if (isWow64)
            {
                var threadContext = new Native.Context {Flags = Native.ContextFlags.ContextControl};

                // Store the thread context structure in a buffer
                
                var threadContextBuffer = Tools.StructureToPointer(threadContext);
                
                // Get the context of the thread and save it in the buffer
                
                if (!Native.GetThreadContext(threadHandle, threadContextBuffer))
                {    
                    ExceptionHandler.ThrowWin32Exception("Failed to get the context of the first thread in the process");
                }
                
                // Read the new thread context structure from the buffer
                
                threadContext = Tools.PointerToStructure<Native.Context>(threadContextBuffer);
                
                // Save the instruction pointer

                var instructionPointer = threadContext.Eip;
                
                // Write the shellcode into the memory of the process

                var shellcodeBytes = Shellcode.CallLoadLibraryx86(instructionPointer, dllPathAddress, loadLibraryAddress);

                try
                {
                    _memoryModule.WriteMemory(processId, shellcodeAddress, shellcodeBytes);
                }

                catch (Win32Exception)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to write the shellcode into the memory of the process");   
                }
                
                // Change the instruction pointer to the shellcode address

                threadContext.Eip = shellcodeAddress;
                
                // Store the thread context structure in a buffer
                
                threadContextBuffer = Tools.StructureToPointer(threadContext);

                // Set the context of the thread with the new context

                if (!Native.SetThreadContext(threadHandle, threadContextBuffer))
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to set the context of the first thread in the process");
                }
            }

            // If the process is x64
            
            else
            {   
                var threadContext = new Native.Context64 {Flags = Native.ContextFlags.ContextControl};

                // Store the thread context structure in a buffer
                
                var threadContextBuffer = Tools.StructureToPointer(threadContext);
                
                // Get the context of the thread and save it in the buffer
                
                if (!Native.GetThreadContext(threadHandle, threadContextBuffer))
                {    
                    ExceptionHandler.ThrowWin32Exception("Failed to get the context of the first thread in the process");
                }

                // Read the new thread context structure from the buffer
                
                threadContext = Tools.PointerToStructure<Native.Context64>(threadContextBuffer);
                
                // Save the instruction pointer

                var instructionPointer = threadContext.Rip;

                // Write the shellcode into the memory of the process

                var shellcodeBytes = Shellcode.CallLoadLibraryx64(instructionPointer, dllPathAddress, loadLibraryAddress);

                try
                {
                    _memoryModule.WriteMemory(processId, shellcodeAddress, shellcodeBytes);
                }

                catch (Win32Exception)
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to write the shellcode into the memory of the process");   
                }
                
                // Change the instruction pointer to the shellcode address

                threadContext.Rip = shellcodeAddress;

                // Store the thread context structure in a buffer
                
                threadContextBuffer = Tools.StructureToPointer(threadContext);
                
                // Set the context of the thread with the new context

                if (!Native.SetThreadContext(threadHandle, threadContextBuffer))
                {
                    ExceptionHandler.ThrowWin32Exception("Failed to set the context of the first thread in the process");
                }
            }
            
            // Resume the suspended thread

            if (Native.ResumeThread(threadHandle) == -1)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to resume the first thread in the process");
            }
            
            // Open a handle to the main window of the process
            
            var windowHandle = new SafeWindowHandle(process.MainWindowHandle);
            
            // Switch to the process to load the dll
            
            Native.SwitchToThisWindow(windowHandle, true);

            // Buffer the execution by 10 milliseconds to avoid freeing memory before it has been referenced
            
            Tools.AsyncWait(10);
            
            // Free the memory previously allocated for the dll path

            try
            {
                _memoryModule.FreeMemory(processId, dllPathAddress);
            }

            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to free the memory allocated for the dll path in the process");   
            }
            
            // Free the memory previously allocated for the shellcode

            try
            {
                _memoryModule.FreeMemory(processId, shellcodeAddress);
            }

            catch (Win32Exception)
            {
                ExceptionHandler.ThrowWin32Exception("Failed to free the memory allocated for the shellcode in the process");   
            }
            
            // Close the handle opened to the process
            
            processHandle?.Close();
            
            // Close the handle opened to the thread
            
            threadHandle?.Close();
            
            return true;
        }
    }
}