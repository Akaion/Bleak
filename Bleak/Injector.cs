using Bleak.Wrappers;

namespace Bleak
{
    public class Injector
    {
        public bool RandomiseDllName;

        #region CreateRemoteThread

        public bool CreateRemoteThread(int processId, byte[] dllBytes)
        {
            using (var methodWrapper = new MethodWrapper(processId, dllBytes, RandomiseDllName, false))
            {
                return methodWrapper.CreateRemoteThread();
            }
        }

        public bool CreateRemoteThread(string processName, byte[] dllBytes)
        {
            using (var methodWrapper = new MethodWrapper(processName, dllBytes, RandomiseDllName, false))
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

        public bool CreateRemoteThread(string processName, string dllPath)
        {
            using (var methodWrapper = new MethodWrapper(processName, dllPath, RandomiseDllName, false))
            {
                return methodWrapper.CreateRemoteThread();
            }
        }

        #endregion

        #region EjectDll

        public bool EjectDll(int processId, byte[] dllBytes)
        {
            using (var extensionWrapper = new ExtensionWrapper(processId, dllBytes, RandomiseDllName))
            {
                return extensionWrapper.EjectDll();
            }
        }

        public bool EjectDll(string processName, byte[] dllBytes)
        {
            using (var extensionWrapper = new ExtensionWrapper(processName, dllBytes, RandomiseDllName))
            {
                return extensionWrapper.EjectDll();
            }
        }

        public bool EjectDll(int processId, string dllPath)
        {
            using (var extensionWrapper = new ExtensionWrapper(processId, dllPath, RandomiseDllName))
            {
                return extensionWrapper.EjectDll();
            }
        }

        public bool EjectDll(string processName, string dllPath)
        {
            using (var extensionWrapper = new ExtensionWrapper(processName, dllPath, RandomiseDllName))
            {
                return extensionWrapper.EjectDll();
            }
        }

        #endregion

        #region EraseDllHeaders

        public bool EraseDllHeaders(int processId, byte[] dllBytes)
        {
            using (var extensionWrapper = new ExtensionWrapper(processId, dllBytes, RandomiseDllName))
            {
                return extensionWrapper.EraseDllHeaders();
            }
        }

        public bool EraseDllHeaders(string processName, byte[] dllBytes)
        {
            using (var extensionWrapper = new ExtensionWrapper(processName, dllBytes, RandomiseDllName))
            {
                return extensionWrapper.EraseDllHeaders();
            }
        }

        public bool EraseDllHeaders(int processId, string dllPath)
        {
            using (var extensionWrapper = new ExtensionWrapper(processId, dllPath, RandomiseDllName))
            {
                return extensionWrapper.EraseDllHeaders();
            }
        }

        public bool EraseDllHeaders(string processName, string dllPath)
        {
            using (var extensionWrapper = new ExtensionWrapper(processName, dllPath, RandomiseDllName))
            {
                return extensionWrapper.EraseDllHeaders();
            }
        }

        #endregion

        #region ManualMap

        public bool ManualMap(int processId, byte[] dllBytes)
        {
            using (var methodWrapper = new MethodWrapper(processId, dllBytes, RandomiseDllName, true))
            {
                return methodWrapper.ManualMap();
            }
        }

        public bool ManualMap(string processName, byte[] dllBytes)
        {
            using (var methodWrapper = new MethodWrapper(processName, dllBytes, RandomiseDllName, true))
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

        public bool ManualMap(string processName, string dllPath)
        {
            using (var methodWrapper = new MethodWrapper(processName, dllPath, RandomiseDllName, true))
            {
                return methodWrapper.ManualMap();
            }
        }

        #endregion

        #region QueueUserApc

        public bool QueueUserApc(int processId, byte[] dllBytes)
        {
            using (var methodWrapper = new MethodWrapper(processId, dllBytes, RandomiseDllName, false))
            {
                return methodWrapper.QueueUserApc();
            }
        }

        public bool QueueUserApc(string processName, byte[] dllBytes)
        {
            using (var methodWrapper = new MethodWrapper(processName, dllBytes, RandomiseDllName, false))
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

        public bool QueueUserApc(string processName, string dllPath)
        {
            using (var methodWrapper = new MethodWrapper(processName, dllPath, RandomiseDllName, false))
            {
                return methodWrapper.QueueUserApc();
            }
        }

        #endregion

        #region RandomiseDllHeaders

        public bool RandomiseDllHeaders(int processId, byte[] dllBytes)
        {
            using (var extensionWrapper = new ExtensionWrapper(processId, dllBytes, RandomiseDllName))
            {
                return extensionWrapper.RandomiseDllHeaders();
            }
        }

        public bool RandomiseDllHeaders(string processName, byte[] dllBytes)
        {
            using (var extensionWrapper = new ExtensionWrapper(processName, dllBytes, RandomiseDllName))
            {
                return extensionWrapper.RandomiseDllHeaders();
            }
        }

        public bool RandomiseDllHeaders(int processId, string dllPath)
        {
            using (var extensionWrapper = new ExtensionWrapper(processId, dllPath, RandomiseDllName))
            {
                return extensionWrapper.RandomiseDllHeaders();
            }
        }

        public bool RandomiseDllHeaders(string processName, string dllPath)
        {
            using (var extensionWrapper = new ExtensionWrapper(processName, dllPath, RandomiseDllName))
            {
                return extensionWrapper.RandomiseDllHeaders();
            }
        }

        #endregion

        #region RtlCreateUserThread

        public bool RtlCreateUserThread(int processId, byte[] dllBytes)
        {
            using (var methodWrapper = new MethodWrapper(processId, dllBytes, RandomiseDllName, false))
            {
                return methodWrapper.RtlCreateUserThread();
            }
        }

        public bool RtlCreateUserThread(string processName, byte[] dllBytes)
        {
            using (var methodWrapper = new MethodWrapper(processName, dllBytes, RandomiseDllName, false))
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

        public bool RtlCreateUserThread(string processName, string dllPath)
        {
            using (var methodWrapper = new MethodWrapper(processName, dllPath, RandomiseDllName, false))
            {
                return methodWrapper.RtlCreateUserThread();
            }
        }

        #endregion

        #region SetThreadContext

        public bool SetThreadContext(int processId, byte[] dllBytes)
        {
            using (var methodWrapper = new MethodWrapper(processId, dllBytes, RandomiseDllName, false))
            {
                return methodWrapper.SetThreadContext();
            }
        }

        public bool SetThreadContext(string processName, byte[] dllBytes)
        {
            using (var methodWrapper = new MethodWrapper(processName, dllBytes, RandomiseDllName, false))
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

        public bool SetThreadContext(string processName, string dllPath)
        {
            using (var methodWrapper = new MethodWrapper(processName, dllPath, RandomiseDllName, false))
            {
                return methodWrapper.SetThreadContext();
            }
        }

        #endregion

        #region UnlinkDllFromPeb

        public bool UnlinkDllFromPeb(int processId, byte[] dllBytes)
        {
            using (var extensionWrapper = new ExtensionWrapper(processId, dllBytes, RandomiseDllName))
            {
                return extensionWrapper.UnlinkDllFromPeb();
            }
        }

        public bool UnlinkDllFromPeb(string processName, byte[] dllBytes)
        {
            using (var extensionWrapper = new ExtensionWrapper(processName, dllBytes, RandomiseDllName))
            {
                return extensionWrapper.UnlinkDllFromPeb();
            }
        }

        public bool UnlinkDllFromPeb(int processId, string dllPath)
        {
            using (var extensionWrapper = new ExtensionWrapper(processId, dllPath, RandomiseDllName))
            {
                return extensionWrapper.UnlinkDllFromPeb();
            }
        }

        public bool UnlinkDllFromPeb(string processName, string dllPath)
        {
            using (var extensionWrapper = new ExtensionWrapper(processName, dllPath, RandomiseDllName))
            {
                return extensionWrapper.UnlinkDllFromPeb();
            }
        }

        #endregion
    }
}
