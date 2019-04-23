using Bleak.Memory;
using Bleak.Native;
using Bleak.Syscall.Objects;
using Bleak.Syscall.Shellcode;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Bleak.Syscall
{
    internal class SyscallManager : IDisposable
    {
        private readonly IntPtr _ntDllAddress;

        private readonly Dictionary<string, SyscallInstance> _syscallCache;

        internal SyscallManager()
        {
            _ntDllAddress = GetNtDllAddress();

            _syscallCache = new Dictionary<string, SyscallInstance>();
        }

        public void Dispose()
        {
            foreach (var syscall in _syscallCache.Values)
            {
                syscall.Dispose();
            }
        }

        private void CreateSyscall<TSyscall>() where TSyscall : class
        {
            // Get the address of the function to syscall

            var functionAddress = PInvoke.GetProcAddress(_ntDllAddress, typeof(TSyscall).Name.Replace("Definition", ""));

            // Copy the first 8 bytes of the function

            var functionBytes = new byte[8];

            Marshal.Copy(functionAddress, functionBytes, 0, 8);

            // Retrieve the syscall index from the bytes

            var syscallIndexBytes = Environment.Is64BitProcess ? functionBytes.Skip(4).Take(4)
                                                               : functionBytes.Skip(1).Take(4);

            // Write the shellcode used to perform the syscall into the local process

            var shellcode = Environment.Is64BitProcess ? SyscallX64.GetShellcode(syscallIndexBytes.ToArray())
                                                       : SyscallX86.GetShellcode(syscallIndexBytes.ToArray());

            var shellcodeBuffer = LocalMemoryTools.StoreBytesInBuffer(shellcode);

            // Create an instance of the syscall class

            var syscallInstance = Activator.CreateInstance(typeof(TSyscall), BindingFlags.Instance | BindingFlags.NonPublic, null, new object[] { shellcodeBuffer }, null);

            // Get the parameter and return types of the syscall method

            var methodInformation = typeof(TSyscall).GetMethod("Invoke", BindingFlags.Instance | BindingFlags.NonPublic);

            var methodTypes = new List<Type>(methodInformation.GetParameters().Select(parameter => parameter.ParameterType))
            {
                methodInformation.ReturnType
            };

            // Create the delegate type to represent the syscall method

            Type delegateType;

            if (methodTypes.Last() == typeof(void))
            {
                methodTypes.RemoveAt(methodTypes.Count - 1);

                delegateType = Expression.GetActionType(methodTypes.ToArray());
            }

            else
            {
                delegateType = Expression.GetFuncType(methodTypes.ToArray());
            }

            // Create a delegate for the syscall method

            var syscallDelegate = Delegate.CreateDelegate(delegateType, syscallInstance, "Invoke");

            _syscallCache.Add(typeof(TSyscall).Name, new SyscallInstance(syscallDelegate, shellcodeBuffer));
        }

        private IntPtr GetNtDllAddress()
        {
            return Process.GetCurrentProcess().Modules.Cast<ProcessModule>().First(module => module.ModuleName.Equals("ntdll.dll")).BaseAddress;
        }

        internal object InvokeSyscall<TSyscall>(params object[] arguments) where TSyscall : class
        {
            if (!_syscallCache.ContainsKey(typeof(TSyscall).Name))
            {
                CreateSyscall<TSyscall>();
            }

            // Invoke the syscall

            try
            {
                return _syscallCache[typeof(TSyscall).Name].SyscallDelegate.DynamicInvoke(arguments);
            }

            catch (TargetInvocationException exception)
            {
                throw exception.InnerException ?? exception;
            }
        }
    }
}
