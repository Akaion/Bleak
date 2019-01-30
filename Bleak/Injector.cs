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
        
        public bool CreateRemoteThread(string processName, byte[] dllBytes)
        {
            var methodWrapper = new MethodWrapper(processName, dllBytes);
            
            return methodWrapper.CreateRemoteThread();
        }
        
        public bool CreateRemoteThread(int processId, byte[] dllBytes)
        {
            var methodWrapper = new MethodWrapper(processId, dllBytes);
            
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
        
        public bool EjectDll(string processName, byte[] dllBytes)
        {
            var extensionWrapper = new ExtensionWrapper(processName, dllBytes);
            
            return extensionWrapper.EjectDll();
        }
        
        public bool EjectDll(int processId, byte[] dllBytes)
        {
            var extensionWrapper = new ExtensionWrapper(processId, dllBytes);
            
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
        
        public bool EraseHeaders(string processName, byte[] dllBytes)
        {
            var extensionWrapper = new ExtensionWrapper(processName, dllBytes);
            
            return extensionWrapper.EraseHeaders();
        }
        
        public bool EraseHeaders(int processId, byte[] dllBytes)
        {
            var extensionWrapper = new ExtensionWrapper(processId, dllBytes);
            
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
        
        public bool ManualMap(string processName, byte[] dllBytes)
        {
            var methodWrapper = new MethodWrapper(processName, dllBytes);
            
            return methodWrapper.ManualMap();
        }
        
        public bool ManualMap(int processId, byte[] dllBytes)
        {
            var methodWrapper = new MethodWrapper(processId, dllBytes);
            
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
        
        public bool NtCreateThreadEx(string processName, byte[] dllBytes)
        {
            var methodWrapper = new MethodWrapper(processName, dllBytes);
            
            return methodWrapper.NtCreateThreadEx();
        }
        
        public bool NtCreateThreadEx(int processId, byte[] dllBytes)
        {
            var methodWrapper = new MethodWrapper(processId, dllBytes);
            
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
        
        public bool QueueUserApc(string processName, byte[] dllBytes)
        {
            var methodWrapper = new MethodWrapper(processName, dllBytes);
            
            return methodWrapper.QueueUserApc();
        }
        
        public bool QueueUserApc(int processId, byte[] dllBytes)
        {
            var methodWrapper = new MethodWrapper(processId, dllBytes);
            
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
        
        public bool RandomiseHeaders(string processName, byte[] dllBytes)
        {
            var extensionWrapper = new ExtensionWrapper(processName, dllBytes);
            
            return extensionWrapper.RandomiseHeaders();
        }
        
        public bool RandomiseHeaders(int processId, byte[] dllBytes)
        {
            var extensionWrapper = new ExtensionWrapper(processId, dllBytes);
            
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
        
        public bool RtlCreateUserThread(string processName, byte[] dllBytes)
        {
            var methodWrapper = new MethodWrapper(processName, dllBytes);
            
            return methodWrapper.RtlCreateUserThread();
        }
        
        public bool RtlCreateUserThread(int processId, byte[] dllBytes)
        {
            var methodWrapper = new MethodWrapper(processId, dllBytes);
            
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
        
        public bool SetThreadContext(string processName, byte[] dllBytes)
        {
            var methodWrapper = new MethodWrapper(processName, dllBytes);
            
            return methodWrapper.SetThreadContext();
        }
        
        public bool SetThreadContext(int processId, byte[] dllBytes)
        {
            var methodWrapper = new MethodWrapper(processId, dllBytes);
            
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
        
        public bool UnlinkFromPeb(string processName, byte[] dllBytes)
        {
            var extensionWrapper = new ExtensionWrapper(processName, dllBytes);
            
            return extensionWrapper.UnlinkFromPeb();
        }
        
        public bool UnlinkFromPeb(int processId, byte[] dllBytes)
        {
            var extensionWrapper = new ExtensionWrapper(processId, dllBytes);
            
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
        
        public bool ZwCreateThreadEx(string processName, byte[] dllBytes)
        {
            var methodWrapper = new MethodWrapper(processName, dllBytes);
            
            return methodWrapper.ZwCreateThreadEx();
        }
        
        public bool ZwCreateThreadEx(int processId, byte[] dllBytes)
        {
            var methodWrapper = new MethodWrapper(processId, dllBytes);

            return methodWrapper.ZwCreateThreadEx();
        }
        
        #endregion
    }
}