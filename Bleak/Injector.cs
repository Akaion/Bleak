using Bleak.Wrappers;

namespace Bleak
{
    public class Injector
    {
        #region CreateRemoteThread
        
        public bool CreateRemoteThread(string processName, string dllPath)
        {
            var methodWrapper = new MethodWrapper(processName, dllPath);

            return methodWrapper.CreateRemoteThread();
        }
        
        public bool CreateRemoteThread(int processId, string dllPath)
        {
            var methodWrapper = new MethodWrapper(processId, dllPath);

            return methodWrapper.CreateRemoteThread();
        }
        
        #endregion
        
        #region EjectDll
        
        public bool EjectDll(string processName, string dllPath)
        {
            var extensionWrapper = new ExtensionWrapper(processName, dllPath);

            return extensionWrapper.EjectDll();
        }
        
        public bool EjectDll(int processId, string dllPath)
        {
            var extensionWrapper = new ExtensionWrapper(processId, dllPath);

            return extensionWrapper.EjectDll();
        }
        
        #endregion
        
        #region EraseHeaders
        
        public bool EraseHeaders(string processName, string dllPath)
        {
            var extensionWrapper = new ExtensionWrapper(processName, dllPath);

            return extensionWrapper.EraseHeaders();
        }
        
        public bool EraseHeaders(int processId, string dllPath)
        {
            var extensionWrapper = new ExtensionWrapper(processId, dllPath);

            return extensionWrapper.EraseHeaders();
        }
        
        #endregion
        
        #region ManualMap
        
        public bool ManualMap(string processName, string dllPath)
        {
            var methodWrapper = new MethodWrapper(processName, dllPath);

            return methodWrapper.ManualMap();
        }
        
        public bool ManualMap(int processId, string dllPath)
        {
            var methodWrapper = new MethodWrapper(processId, dllPath);

            return methodWrapper.ManualMap();
        }
        
        #endregion
        
        #region NtCreateThreadEx
        
        public bool NtCreateThreadEx(string processName, string dllPath)
        {
            var methodWrapper = new MethodWrapper(processName, dllPath);

            return methodWrapper.NtCreateThreadEx();
        }
        
        public bool NtCreateThreadEx(int processId, string dllPath)
        {
            var methodWrapper = new MethodWrapper(processId, dllPath);

            return methodWrapper.NtCreateThreadEx();
        }
        
        #endregion
        
        #region QueueUserApc
        
        public bool QueueUserApc(string processName, string dllPath)
        {
            var methodWrapper = new MethodWrapper(processName, dllPath);

            return methodWrapper.QueueUserApc();
        }
        
        public bool QueueUserApc(int processId, string dllPath)
        {
            var methodWrapper = new MethodWrapper(processId, dllPath);

            return methodWrapper.QueueUserApc();
        }
        
        #endregion
        
        #region RandomiseHeaders
        
        public bool RandomiseHeaders(string processName, string dllPath)
        {
            var extensionWrapper = new ExtensionWrapper(processName, dllPath);

            return extensionWrapper.RandomiseHeaders();
        }
        
        public bool RandomiseHeaders(int processId, string dllPath)
        {
            var extensionWrapper = new ExtensionWrapper(processId, dllPath);

            return extensionWrapper.RandomiseHeaders();
        }
        
        #endregion
        
        #region RtlCreateUserThread
        
        public bool RtlCreateUserThread(string processName, string dllPath)
        {
            var methodWrapper = new MethodWrapper(processName, dllPath);

            return methodWrapper.RtlCreateUserThread();
        }
        
        public bool RtlCreateUserThread(int processId, string dllPath)
        {
            var methodWrapper = new MethodWrapper(processId, dllPath);

            return methodWrapper.RtlCreateUserThread();
        }
        
        #endregion
        
        #region SetThreadContext
        
        public bool SetThreadContext(string processName, string dllPath)
        {
            var methodWrapper = new MethodWrapper(processName, dllPath);

            return methodWrapper.SetThreadContext();
        }
        
        public bool SetThreadContext(int processId, string dllPath)
        {
            var methodWrapper = new MethodWrapper(processId, dllPath);

            return methodWrapper.SetThreadContext();
        }
        
        #endregion
        
        #region UnlinkFromPeb

        public bool UnlinkFromPeb(string processName, string dllPath)
        {
            var extensionWrapper = new ExtensionWrapper(processName, dllPath);

            return extensionWrapper.UnlinkFromPeb();
        }
        
        public bool UnlinkFromPeb(int processId, string dllPath)
        {
            var extensionWrapper = new ExtensionWrapper(processId, dllPath);

            return extensionWrapper.UnlinkFromPeb();
        }
        
        #endregion
        
        #region ZwCreateThreadEx
        
        public bool ZwCreateThreadEx(string processName, string dllPath)
        {
            var methodWrapper = new MethodWrapper(processName, dllPath);

            return methodWrapper.ZwCreateThreadEx();
        }
        
        public bool ZwCreateThreadEx(int processId, string dllPath)
        {
            var methodWrapper = new MethodWrapper(processId, dllPath);

            return methodWrapper.ZwCreateThreadEx();
        }
        
        #endregion
    }
}