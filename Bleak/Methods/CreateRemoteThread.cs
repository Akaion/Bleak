using Bleak.Native;
using Bleak.SafeHandle;
using Bleak.Syscall.Definitions;
using Bleak.Wrappers;
using System.Text;

namespace Bleak.Methods
{
    internal class CreateRemoteThread
    {
        private readonly PropertyWrapper _propertyWrapper;

        internal CreateRemoteThread(PropertyWrapper propertyWrapper)
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

            // Create a thread to call LoadLibraryW in the target process

            var remoteThreadHandle = (SafeThreadHandle) _propertyWrapper.SyscallManager.InvokeSyscall<NtCreateThreadEx>(_propertyWrapper.TargetProcess.Handle, loadLibraryAddress, dllPathBuffer);

            PInvoke.WaitForSingleObject(remoteThreadHandle, uint.MaxValue);

            _propertyWrapper.MemoryManager.FreeVirtualMemory(dllPathBuffer);

            remoteThreadHandle.Dispose();

            return true;
        }
    }
}
