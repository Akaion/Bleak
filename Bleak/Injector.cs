using Bleak.Wrappers;

namespace Bleak
{
    public class Injector
    {
        public bool RandomiseDllName;

        #region CreateRemoteThread

        public bool CreateRemoteThread(string processName, byte[] dllBytes)
        {
            using (var methodWrapper = new MethodWrapper(processName, dllBytes, RandomiseDllName, false))
            {
                return methodWrapper.CreateRemoteThread();
            }
        }

        public bool CreateRemoteThread(int processId, byte[] dllBytes)
        {
            using (var methodWrapper = new MethodWrapper(processId, dllBytes, RandomiseDllName, false))
            {
                return methodWrapper.CreateRemoteThread();
            }
        }

        public bool CreateRemoteThread(string processName, string dllPath)
        {
            using (var methodWrapper = new MethodWrapper(processName, dllPath, RandomiseDllName, false))
            {
                return methodWrapper.CreateRemoteThread();
            }
        }

        public bool CreateRemoteThread(int processId, string dllPath)
        {
            using (var methodWrapper = new MethodWrapper(processId, dllPath, RandomiseDllName, false))
            {
                return methodWrapper.CreateRemoteThread();
            }
        }

        #endregion

        #region EjectDll

        public bool EjectDll(string processName, byte[] dllBytes)
        {
            using (var methodWrapper = new ExtensionWrapper(processName, dllBytes))
            {
                return methodWrapper.EjectDll();
            }
        }

        public bool EjectDll(int processId, byte[] dllBytes)
        {
            using (var methodWrapper = new ExtensionWrapper(processId, dllBytes))
            {
                return methodWrapper.EjectDll();
            }
        }

        public bool EjectDll(string processName, string dllPath)
        {
            using (var methodWrapper = new ExtensionWrapper(processName, dllPath))
            {
                return methodWrapper.EjectDll();
            }
        }

        public bool EjectDll(int processId, string dllPath)
        {
            using (var methodWrapper = new ExtensionWrapper(processId, dllPath))
            {
                return methodWrapper.EjectDll();
            }
        }

        #endregion

        #region EraseHeaders

        public bool EraseHeaders(string processName, byte[] dllBytes)
        {
            using (var methodWrapper = new ExtensionWrapper(processName, dllBytes))
            {
                return methodWrapper.EraseHeaders();
            }
        }

        public bool EraseHeaders(int processId, byte[] dllBytes)
        {
            using (var methodWrapper = new ExtensionWrapper(processId, dllBytes))
            {
                return methodWrapper.EraseHeaders();
            }
        }

        public bool EraseHeaders(string processName, string dllPath)
        {
            using (var methodWrapper = new ExtensionWrapper(processName, dllPath))
            {
                return methodWrapper.EraseHeaders();
            }
        }

        public bool EraseHeaders(int processId, string dllPath)
        {
            using (var methodWrapper = new ExtensionWrapper(processId, dllPath))
            {
                return methodWrapper.EraseHeaders();
            }
        }

        #endregion

        #region NtCreateThreadEx

        public bool NtCreateThreadEx(string processName, byte[] dllBytes)
        {
            using (var methodWrapper = new MethodWrapper(processName, dllBytes, RandomiseDllName, false))
            {
                return methodWrapper.NtCreateThreadEx();
            }
        }

        public bool NtCreateThreadEx(int processId, byte[] dllBytes)
        {
            using (var methodWrapper = new MethodWrapper(processId, dllBytes, RandomiseDllName, false))
            {
                return methodWrapper.NtCreateThreadEx();
            }
        }

        public bool NtCreateThreadEx(string processName, string dllPath)
        {
            using (var methodWrapper = new MethodWrapper(processName, dllPath, RandomiseDllName, false))
            {
                return methodWrapper.NtCreateThreadEx();
            }
        }

        public bool NtCreateThreadEx(int processId, string dllPath)
        {
            using (var methodWrapper = new MethodWrapper(processId, dllPath, RandomiseDllName, false))
            {
                return methodWrapper.NtCreateThreadEx();
            }
        }

        #endregion

        #region ManualMap

        public bool ManualMap(string processName, byte[] dllBytes)
        {
            using (var methodWrapper = new MethodWrapper(processName, dllBytes, RandomiseDllName, true))
            {
                return methodWrapper.ManualMap();
            }
        }

        public bool ManualMap(int processId, byte[] dllBytes)
        {
            using (var methodWrapper = new MethodWrapper(processId, dllBytes, RandomiseDllName, true))
            {
                return methodWrapper.ManualMap();
            }
        }

        public bool ManualMap(string processName, string dllPath)
        {
            using (var methodWrapper = new MethodWrapper(processName, dllPath, RandomiseDllName, true))
            {
                return methodWrapper.ManualMap();
            }
        }

        public bool ManualMap(int processId, string dllPath)
        {
            using (var methodWrapper = new MethodWrapper(processId, dllPath, RandomiseDllName, true))
            {
                return methodWrapper.ManualMap();
            }
        }

        #endregion

        #region QueueUserApc

        public bool QueueUserApc(string processName, byte[] dllBytes)
        {
            using (var methodWrapper = new MethodWrapper(processName, dllBytes, RandomiseDllName, false))
            {
                return methodWrapper.QueueUserApc();
            }
        }

        public bool QueueUserApc(int processId, byte[] dllBytes)
        {
            using (var methodWrapper = new MethodWrapper(processId, dllBytes, RandomiseDllName, false))
            {
                return methodWrapper.QueueUserApc();
            }
        }

        public bool QueueUserApc(string processName, string dllPath)
        {
            using (var methodWrapper = new MethodWrapper(processName, dllPath, RandomiseDllName, false))
            {
                return methodWrapper.QueueUserApc();
            }
        }

        public bool QueueUserApc(int processId, string dllPath)
        {
            using (var methodWrapper = new MethodWrapper(processId, dllPath, RandomiseDllName, false))
            {
                return methodWrapper.QueueUserApc();
            }
        }

        #endregion

        #region RandomiseHeaders

        public bool RandomiseHeaders(string processName, byte[] dllBytes)
        {
            using (var methodWrapper = new ExtensionWrapper(processName, dllBytes))
            {
                return methodWrapper.RandomiseHeaders();
            }
        }

        public bool RandomiseHeaders(int processId, byte[] dllBytes)
        {
            using (var methodWrapper = new ExtensionWrapper(processId, dllBytes))
            {
                return methodWrapper.RandomiseHeaders();
            }
        }

        public bool RandomiseHeaders(string processName, string dllPath)
        {
            using (var methodWrapper = new ExtensionWrapper(processName, dllPath))
            {
                return methodWrapper.RandomiseHeaders();
            }
        }

        public bool RandomiseHeaders(int processId, string dllPath)
        {
            using (var methodWrapper = new ExtensionWrapper(processId, dllPath))
            {
                return methodWrapper.RandomiseHeaders();
            }
        }

        #endregion

        #region RtlCreateUserThread

        public bool RtlCreateUserThread(string processName, byte[] dllBytes)
        {
            using (var methodWrapper = new MethodWrapper(processName, dllBytes, RandomiseDllName, false))
            {
                return methodWrapper.RtlCreateUserThread();
            }
        }

        public bool RtlCreateUserThread(int processId, byte[] dllBytes)
        {
            using (var methodWrapper = new MethodWrapper(processId, dllBytes, RandomiseDllName, false))
            {
                return methodWrapper.RtlCreateUserThread();
            }
        }

        public bool RtlCreateUserThread(string processName, string dllPath)
        {
            using (var methodWrapper = new MethodWrapper(processName, dllPath, RandomiseDllName, false))
            {
                return methodWrapper.RtlCreateUserThread();
            }
        }

        public bool RtlCreateUserThread(int processId, string dllPath)
        {
            using (var methodWrapper = new MethodWrapper(processId, dllPath, RandomiseDllName, false))
            {
                return methodWrapper.RtlCreateUserThread();
            }
        }

        #endregion

        #region SetThreadContext

        public bool SetThreadContext(string processName, byte[] dllBytes)
        {
            using (var methodWrapper = new MethodWrapper(processName, dllBytes, RandomiseDllName, false))
            {
                return methodWrapper.SetThreadContext();
            }
        }

        public bool SetThreadContext(int processId, byte[] dllBytes)
        {
            using (var methodWrapper = new MethodWrapper(processId, dllBytes, RandomiseDllName, false))
            {
                return methodWrapper.SetThreadContext();
            }
        }

        public bool SetThreadContext(string processName, string dllPath)
        {
            using (var methodWrapper = new MethodWrapper(processName, dllPath, RandomiseDllName, false))
            {
                return methodWrapper.SetThreadContext();
            }
        }

        public bool SetThreadContext(int processId, string dllPath)
        {
            using (var methodWrapper = new MethodWrapper(processId, dllPath, RandomiseDllName, false))
            {
                return methodWrapper.SetThreadContext();
            }
        }

        #endregion

        #region UnlinkFromPeb

        public bool UnlinkFromPeb(string processName, byte[] dllBytes)
        {
            using (var methodWrapper = new ExtensionWrapper(processName, dllBytes))
            {
                return methodWrapper.UnlinkFromPeb();
            }
        }

        public bool UnlinkFromPeb(int processId, byte[] dllBytes)
        {
            using (var methodWrapper = new ExtensionWrapper(processId, dllBytes))
            {
                return methodWrapper.UnlinkFromPeb();
            }
        }

        public bool UnlinkFromPeb(string processName, string dllPath)
        {
            using (var methodWrapper = new ExtensionWrapper(processName, dllPath))
            {
                return methodWrapper.UnlinkFromPeb();
            }
        }

        public bool UnlinkFromPeb(int processId, string dllPath)
        {
            using (var methodWrapper = new ExtensionWrapper(processId, dllPath))
            {
                return methodWrapper.UnlinkFromPeb();
            }
        }

        #endregion
    }
}
