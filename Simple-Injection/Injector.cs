using Simple_Injection.Methods;
using Simple_Injection.Extensions;

namespace Simple_Injection
{
    public class Injector
    {
        public bool CreateRemoteThread(string dllPath, string processName)
        {
            return Methods.CreateRemoteThread.Inject(dllPath, processName);
        }
        
        // CreateRemoteThread processId overload
        
        public bool CreateRemoteThread(string dllPath, int processId)
        {
            return Methods.CreateRemoteThread.Inject(dllPath, processId);
        }

        public bool ManualMap(string dllPath, string processName)
        {
            return Methods.ManualMap.Inject(dllPath, processName);
        }
        
        // ManualMap processId overload
        
        public bool ManualMap(string dllPath, int processId)
        {
            return Methods.ManualMap.Inject(dllPath, processId);
        }

        public bool QueueUserAPC(string dllPath, string processName)
        {
            return Methods.QueueUserAPC.Inject(dllPath, processName);
        }
        
        // QueueUserAPC processId overload
        
        public bool QueueUserAPC(string dllPath, int processId)
        {
            return Methods.QueueUserAPC.Inject(dllPath, processId);
        }
        
        public bool RtlCreateUserThread(string dllPath, string processName)
        {
            return Methods.RtlCreateUserThread.Inject(dllPath, processName);
        }
        
        // RtlCreateUserThread processId overload
        
        public bool RtlCreateUserThread(string dllPath, int processId)
        {
            return Methods.RtlCreateUserThread.Inject(dllPath, processId);
        }
        
        public bool SetThreadContext(string dllPath, string processName)
        {
            return Methods.SetThreadContext.Inject(dllPath, processName);
        }
        
        // SetThreadContext processId overload
        
        public bool SetThreadContext(string dllPath, int processId)
        {
            return Methods.SetThreadContext.Inject(dllPath, processId);
        }

        public bool EraseHeaders(string dllPath, string processName)
        {
            return Extensions.EraseHeaders.Erase(dllPath, processName);
        }
        
        // EraseHeaders processId overload
        
        public bool EraseHeaders(string dllPath, int processId)
        {
            return Extensions.EraseHeaders.Erase(dllPath, processId);
        }

        public bool RandomiseHeaders(string dllPath, string processName)
        {
            return Extensions.RandomiseHeaders.Randomise(dllPath, processName);
        }
        
        // RandomiseHeaders processId overload
        
        public bool RandomiseHeaders(string dllPath, int processId)
        {
            return Extensions.RandomiseHeaders.Randomise(dllPath, processId);
        }
    }
}
