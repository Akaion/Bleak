namespace Simple_Injection
{
    public class Injector
    {
        public bool CreateRemoteThread(string dllPath, string processName)
        {
            return Methods.CreateRemoteThread.Inject(dllPath, processName);
        }
       
        public bool CreateRemoteThread(string dllPath, int processId)
        {
            return Methods.CreateRemoteThread.Inject(dllPath, processId);
        }

        public bool ManualMap(string dllPath, string processName)
        {
            return Methods.ManualMap.Inject(dllPath, processName);
        }
        
        public bool ManualMap(string dllPath, int processId)
        {
            return Methods.ManualMap.Inject(dllPath, processId);
        }

        public bool QueueUserAPC(string dllPath, string processName)
        {
            return Methods.QueueUserAPC.Inject(dllPath, processName);
        }
        
        public bool QueueUserAPC(string dllPath, int processId)
        {
            return Methods.QueueUserAPC.Inject(dllPath, processId);
        }
        
        public bool RtlCreateUserThread(string dllPath, string processName)
        {
            return Methods.RtlCreateUserThread.Inject(dllPath, processName);
        }
        
        public bool RtlCreateUserThread(string dllPath, int processId)
        {
            return Methods.RtlCreateUserThread.Inject(dllPath, processId);
        }
        
        public bool SetThreadContext(string dllPath, string processName)
        {
            return Methods.SetThreadContext.Inject(dllPath, processName);
        }
        
        public bool SetThreadContext(string dllPath, int processId)
        {
            return Methods.SetThreadContext.Inject(dllPath, processId);
        }

        public bool EraseHeaders(string dllPath, string processName)
        {
            return Extensions.EraseHeaders.Erase(dllPath, processName);
        }
        
        public bool EraseHeaders(string dllPath, int processId)
        {
            return Extensions.EraseHeaders.Erase(dllPath, processId);
        }

        public bool RandomiseHeaders(string dllPath, string processName)
        {
            return Extensions.RandomiseHeaders.Randomise(dllPath, processName);
        }
        
        public bool RandomiseHeaders(string dllPath, int processId)
        {
            return Extensions.RandomiseHeaders.Randomise(dllPath, processId);
        }
    }
}
