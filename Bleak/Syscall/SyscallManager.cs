using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;

namespace Bleak.Syscall
{
    internal class SyscallManager : IDisposable
    {
        private readonly Dictionary<string, Tuple<IDisposable, Delegate>> Syscalls;

        private readonly Tools SyscallTools;

        internal SyscallManager()
        {
            Syscalls = new Dictionary<string, Tuple<IDisposable, Delegate>>();

            SyscallTools = new Tools();
        }

        public void Dispose()
        {
            foreach (var syscall in Syscalls.Values)
            {
                syscall.Item1.Dispose();
            }
        }

        private void InitialiseSyscall<TSyscall>() where TSyscall : class
        {
            // Create an instance of the syscall class

            var syscallInstance = (IDisposable) Activator.CreateInstance(typeof(TSyscall), BindingFlags.Instance | BindingFlags.NonPublic, null, new object[] { SyscallTools }, null);

            // Get the parameter and return types of the syscall

            var methodInformation = typeof(TSyscall).GetMethod("Invoke", BindingFlags.Instance | BindingFlags.NonPublic);
            
            var methodTypes = new List<Type>(methodInformation.GetParameters().Select(parameter => parameter.ParameterType))
            {
                methodInformation.ReturnType
            };
            
            // Create the type of the delegate to be created

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
            
            Syscalls.Add(typeof(TSyscall).Name, Tuple.Create(syscallInstance, methodDelegate));
        }

        internal object InvokeSyscall<TSyscall>(params object[] parameters) where TSyscall : class
        {
            if (!Syscalls.ContainsKey(typeof(TSyscall).Name))
            {
                // Create a new syscall
                
                InitialiseSyscall<TSyscall>();
            }

            // Perform the syscall

            return Syscalls[typeof(TSyscall).Name].Item2.DynamicInvoke(parameters);
        }
    }
}
