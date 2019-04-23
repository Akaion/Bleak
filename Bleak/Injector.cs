using Bleak.Injection;
using Bleak.Injection.Extensions;
using Bleak.Injection.Methods;

namespace Bleak
{
    public class Injector
    {
        public bool RandomiseDllName;

        #region CreateRemoteThread

        public bool CreateRemoteThread(int targetProcessId, byte[] dllBytes)
        {
            using (var injectionManager = new InjectionManager(targetProcessId, dllBytes, false, false, RandomiseDllName))
            {
                return injectionManager.CallInjectionMethod<CreateRemoteThread>();
            }
        }

        public bool CreateRemoteThread(int targetProcessId, string dllPath)
        {
            using (var injectionManager = new InjectionManager(targetProcessId, dllPath, false, RandomiseDllName))
            {
                return injectionManager.CallInjectionMethod<CreateRemoteThread>();
            }
        }

        public bool CreateRemoteThread(string targetProcessName, byte[] dllBytes)
        {
            using (var injectionManager = new InjectionManager(targetProcessName, dllBytes, false, false, RandomiseDllName))
            {
                return injectionManager.CallInjectionMethod<CreateRemoteThread>();
            }
        }

        public bool CreateRemoteThread(string targetProcessName, string dllPath)
        {
            using (var injectionManager = new InjectionManager(targetProcessName, dllPath, false, RandomiseDllName))
            {
                return injectionManager.CallInjectionMethod<CreateRemoteThread>();
            }
        }

        #endregion

        #region EjectDll

        public bool EjectDll(int targetProcessId, byte[] dllBytes)
        {
            using (var injectionManager = new InjectionManager(targetProcessId, dllBytes, false, true, RandomiseDllName))
            {
                return injectionManager.CallInjectionExtension<EjectDll>();
            }
        }

        public bool EjectDll(int targetProcessId, string dllPath)
        {
            using (var injectionManager = new InjectionManager(targetProcessId, dllPath, true, RandomiseDllName))
            {
                return injectionManager.CallInjectionExtension<EjectDll>();
            }
        }

        public bool EjectDll(string targetProcessName, byte[] dllBytes)
        {
            using (var injectionManager = new InjectionManager(targetProcessName, dllBytes, false, true, RandomiseDllName))
            {
                return injectionManager.CallInjectionExtension<EjectDll>();
            }
        }

        public bool EjectDll(string targetProcessName, string dllPath)
        {
            using (var injectionManager = new InjectionManager(targetProcessName, dllPath, true, RandomiseDllName))
            {
                return injectionManager.CallInjectionExtension<EjectDll>();
            }
        }

        #endregion

        #region EraseDllHeaders

        public bool EraseDllHeaders(int targetProcessId, byte[] dllBytes)
        {
            using (var injectionManager = new InjectionManager(targetProcessId, dllBytes, false, true, RandomiseDllName))
            {
                return injectionManager.CallInjectionExtension<EraseDllHeaders>();
            }
        }

        public bool EraseDllHeaders(int targetProcessId, string dllPath)
        {
            using (var injectionManager = new InjectionManager(targetProcessId, dllPath, true, RandomiseDllName))
            {
                return injectionManager.CallInjectionExtension<EraseDllHeaders>();
            }
        }

        public bool EraseDllHeaders(string targetProcessName, byte[] dllBytes)
        {
            using (var injectionManager = new InjectionManager(targetProcessName, dllBytes, false, true, RandomiseDllName))
            {
                return injectionManager.CallInjectionExtension<EraseDllHeaders>();
            }
        }

        public bool EraseDllHeaders(string targetProcessName, string dllPath)
        {
            using (var injectionManager = new InjectionManager(targetProcessName, dllPath, true, RandomiseDllName))
            {
                return injectionManager.CallInjectionExtension<EraseDllHeaders>();
            }
        }

        #endregion

        #region ManualMap

        public bool ManualMap(int targetProcessId, byte[] dllBytes)
        {
            using (var injectionManager = new InjectionManager(targetProcessId, dllBytes, true, false, RandomiseDllName))
            {
                return injectionManager.CallInjectionMethod<ManualMap>();
            }
        }

        public bool ManualMap(int targetProcessId, string dllPath)
        {
            using (var injectionManager = new InjectionManager(targetProcessId, dllPath, false, RandomiseDllName))
            {
                return injectionManager.CallInjectionMethod<ManualMap>();
            }
        }

        public bool ManualMap(string targetProcessName, byte[] dllBytes)
        {
            using (var injectionManager = new InjectionManager(targetProcessName, dllBytes, true, false, RandomiseDllName))
            {
                return injectionManager.CallInjectionMethod<ManualMap>();
            }
        }

        public bool ManualMap(string targetProcessName, string dllPath)
        {
            using (var injectionManager = new InjectionManager(targetProcessName, dllPath, false, RandomiseDllName))
            {
                return injectionManager.CallInjectionMethod<ManualMap>();
            }
        }

        #endregion

        #region QueueUserApc

        public bool QueueUserApc(int targetProcessId, byte[] dllBytes)
        {
            using (var injectionManager = new InjectionManager(targetProcessId, dllBytes, false, false, RandomiseDllName))
            {
                return injectionManager.CallInjectionMethod<QueueUserApc>();
            }
        }

        public bool QueueUserApc(int targetProcessId, string dllPath)
        {
            using (var injectionManager = new InjectionManager(targetProcessId, dllPath, false, RandomiseDllName))
            {
                return injectionManager.CallInjectionMethod<QueueUserApc>();
            }
        }

        public bool QueueUserApc(string targetProcessName, byte[] dllBytes)
        {
            using (var injectionManager = new InjectionManager(targetProcessName, dllBytes, false, false, RandomiseDllName))
            {
                return injectionManager.CallInjectionMethod<QueueUserApc>();
            }
        }

        public bool QueueUserApc(string targetProcessName, string dllPath)
        {
            using (var injectionManager = new InjectionManager(targetProcessName, dllPath, false, RandomiseDllName))
            {
                return injectionManager.CallInjectionMethod<QueueUserApc>();
            }
        }

        #endregion

        #region RandomiseDllHeaders

        public bool RandomiseDllHeaders(int targetProcessId, byte[] dllBytes)
        {
            using (var injectionManager = new InjectionManager(targetProcessId, dllBytes, false, true, RandomiseDllName))
            {
                return injectionManager.CallInjectionExtension<RandomiseDllHeaders>();
            }
        }

        public bool RandomiseDllHeaders(int targetProcessId, string dllPath)
        {
            using (var injectionManager = new InjectionManager(targetProcessId, dllPath, true, RandomiseDllName))
            {
                return injectionManager.CallInjectionExtension<RandomiseDllHeaders>();
            }
        }

        public bool RandomiseDllHeaders(string targetProcessName, byte[] dllBytes)
        {
            using (var injectionManager = new InjectionManager(targetProcessName, dllBytes, false, true, RandomiseDllName))
            {
                return injectionManager.CallInjectionExtension<RandomiseDllHeaders>();
            }
        }

        public bool RandomiseDllHeaders(string targetProcessName, string dllPath)
        {
            using (var injectionManager = new InjectionManager(targetProcessName, dllPath, true, RandomiseDllName))
            {
                return injectionManager.CallInjectionExtension<RandomiseDllHeaders>();
            }
        }

        #endregion

        #region RtlCreateUserThread

        public bool RtlCreateUserThread(int targetProcessId, byte[] dllBytes)
        {
            using (var injectionManager = new InjectionManager(targetProcessId, dllBytes, false, false, RandomiseDllName))
            {
                return injectionManager.CallInjectionMethod<RtlCreateUserThread>();
            }
        }

        public bool RtlCreateUserThread(int targetProcessId, string dllPath)
        {
            using (var injectionManager = new InjectionManager(targetProcessId, dllPath, false, RandomiseDllName))
            {
                return injectionManager.CallInjectionMethod<RtlCreateUserThread>();
            }
        }

        public bool RtlCreateUserThread(string targetProcessName, byte[] dllBytes)
        {
            using (var injectionManager = new InjectionManager(targetProcessName, dllBytes, false, false, RandomiseDllName))
            {
                return injectionManager.CallInjectionMethod<RtlCreateUserThread>();
            }
        }

        public bool RtlCreateUserThread(string targetProcessName, string dllPath)
        {
            using (var injectionManager = new InjectionManager(targetProcessName, dllPath, false, RandomiseDllName))
            {
                return injectionManager.CallInjectionMethod<RtlCreateUserThread>();
            }
        }

        #endregion

        #region ThreadHijack

        public bool ThreadHijack(int targetProcessId, byte[] dllBytes)
        {
            using (var injectionManager = new InjectionManager(targetProcessId, dllBytes, false, false, RandomiseDllName))
            {
                return injectionManager.CallInjectionMethod<ThreadHijack>();
            }
        }

        public bool ThreadHijack(int targetProcessId, string dllPath)
        {
            using (var injectionManager = new InjectionManager(targetProcessId, dllPath, false, RandomiseDllName))
            {
                return injectionManager.CallInjectionMethod<ThreadHijack>();
            }
        }

        public bool ThreadHijack(string targetProcessName, byte[] dllBytes)
        {
            using (var injectionManager = new InjectionManager(targetProcessName, dllBytes, false, false, RandomiseDllName))
            {
                return injectionManager.CallInjectionMethod<ThreadHijack>();
            }
        }

        public bool ThreadHijack(string targetProcessName, string dllPath)
        {
            using (var injectionManager = new InjectionManager(targetProcessName, dllPath, false, RandomiseDllName))
            {
                return injectionManager.CallInjectionMethod<ThreadHijack>();
            }
        }

        #endregion

        #region UnlinkDllFromPeb

        public bool UnlinkDllFromPeb(int targetProcessId, byte[] dllBytes)
        {
            using (var injectionManager = new InjectionManager(targetProcessId, dllBytes, false, true, RandomiseDllName))
            {
                return injectionManager.CallInjectionExtension<UnlinkDllFromPeb>();
            }
        }

        public bool UnlinkDllFromPeb(int targetProcessId, string dllPath)
        {
            using (var injectionManager = new InjectionManager(targetProcessId, dllPath, true, RandomiseDllName))
            {
                return injectionManager.CallInjectionExtension<UnlinkDllFromPeb>();
            }
        }

        public bool UnlinkDllFromPeb(string targetProcessName, byte[] dllBytes)
        {
            using (var injectionManager = new InjectionManager(targetProcessName, dllBytes, false, true, RandomiseDllName))
            {
                return injectionManager.CallInjectionExtension<UnlinkDllFromPeb>();
            }
        }

        public bool UnlinkDllFromPeb(string targetProcessName, string dllPath)
        {
            using (var injectionManager = new InjectionManager(targetProcessName, dllPath, true, RandomiseDllName))
            {
                return injectionManager.CallInjectionExtension<UnlinkDllFromPeb>();
            }
        }

        #endregion
    }
}
