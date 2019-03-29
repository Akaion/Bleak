using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;

namespace Bleak.Syscall
{
    internal class SyscallManager : IDisposable
    {
        private readonly Dictionary<string, Delegate> _syscalls;

        private readonly Tools _syscallTools;

        internal SyscallManager()
        {
            _syscalls = new Dictionary<string, Delegate>();

            _syscallTools = new Tools();
        }

        public void Dispose()
        {
            _syscallTools.Dispose();
        }

        private void CreateSyscall<TSyscall>() where TSyscall : class
        {
            // Create an instance of the syscall class

            var syscallInstance = Activator.CreateInstance(typeof(TSyscall), BindingFlags.Instance | BindingFlags.NonPublic, null, new object[] { _syscallTools }, null);

            // Get the parameter and return types of the syscall

            var methodInformation = typeof(TSyscall).GetMethod("Invoke", BindingFlags.Instance | BindingFlags.NonPublic);

            var methodTypes = new List<Type>(methodInformation.GetParameters().Select(parameter => parameter.ParameterType))
            {
                methodInformation.ReturnType
            };

            // Create the delegate type for the syscall

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

            // Create a delegate to perform the syscall

            var methodDelegate = Delegate.CreateDelegate(delegateType, syscallInstance, "Invoke");

            _syscalls.Add(typeof(TSyscall).Name, methodDelegate);
        }

        internal object InvokeSyscall<TSyscall>(params object[] arguments) where TSyscall : class
        {
            if (!_syscalls.ContainsKey(typeof(TSyscall).Name))
            {
                CreateSyscall<TSyscall>();
            }

            // Perform the syscall

            return _syscalls[typeof(TSyscall).Name].DynamicInvoke(arguments);
        }
    }
}
