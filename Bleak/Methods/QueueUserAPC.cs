using Bleak.Native;
using Bleak.SafeHandle;
using Bleak.Syscall.Definitions;
using Bleak.Wrappers;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace Bleak.Methods
{
    internal class QueueUserApc
    {
        private readonly PropertyWrapper _propertyWrapper;

        internal QueueUserApc(PropertyWrapper propertyWrapper)
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

            foreach (var thread in _propertyWrapper.TargetProcess.Process.Threads.Cast<ProcessThread>())
            {
                // Open a handle to the thread

                var threadHandle = (SafeThreadHandle) _propertyWrapper.SyscallManager.InvokeSyscall<NtOpenThread>(thread.Id);

                // Add an APC to call LoadLibraryW to the APC queue of the thread

                _propertyWrapper.SyscallManager.InvokeSyscall<NtQueueApcThread>(threadHandle, loadLibraryAddress, dllPathBuffer);

                threadHandle.Dispose();
            }

            _propertyWrapper.MemoryManager.FreeVirtualMemory(dllPathBuffer);

            return true;
        }
    }
}
