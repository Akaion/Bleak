using Simple_Injection.Methods;
using Simple_Injection.Extensions;

namespace Simple_Injection
{
    public class Injector
    {
        public bool CreateRemoteThread(string dllPath, string processName)
        {
            return MCreateRemoteThread.Inject(dllPath, processName);
        }
        
        // CreateRemoteThread processId overload
        
        public bool CreateRemoteThread(string dllPath, int processId)
        {
            return MCreateRemoteThread.Inject(dllPath, processId);
        }

        public bool ManualMap(string dllPath, string processName)
        {
            return MManualMap.Inject(dllPath, processName);
        }
        
        // ManualMap processId overload
        
        public bool ManualMap(string dllPath, int processId)
        {
            return MManualMap.Inject(dllPath, processId);
        }

        public bool QueueUserAPC(string dllPath, string processName)
        {
            return MQueueUserAPC.Inject(dllPath, processName);
        }
        
        // QueueUserAPC processId overload
        
        public bool QueueUserAPC(string dllPath, int processId)
        {
            return MQueueUserAPC.Inject(dllPath, processId);
        }
        
        public bool RtlCreateUserThread(string dllPath, string processName)
        {
            return MRtlCreateUserThread.Inject(dllPath, processName);
        }
        
        // RtlCreateUserThread processId overload
        
        public bool RtlCreateUserThread(string dllPath, int processId)
        {
            return MRtlCreateUserThread.Inject(dllPath, processId);
        }
        
        public bool SetThreadContext(string dllPath, string processName)
        {
            return MSetThreadContext.Inject(dllPath, processName);
        }
        
        // SetThreadContext processId overload
        
        public bool SetThreadContext(string dllPath, int processId)
        {
            return MSetThreadContext.Inject(dllPath, processId);
        }

        public bool EraseHeaders(string dllPath, string processName)
        {
            return MEraseHeaders.Erase(dllPath, processName);
        }
        
        // EraseHeaders processId overload
        
        public bool EraseHeaders(string dllPath, int processId)
        {
            return MEraseHeaders.Erase(dllPath, processId);
        }

        public bool RandomiseHeaders(string dllPath, string processName)
        {
            return MRandomiseHeaders.Randomise(dllPath, processName);
        }
        
        // RandomiseHeaders processId overload
        
        public bool RandomiseHeaders(string dllPath, int processId)
        {
            return MRandomiseHeaders.Randomise(dllPath, processId);
        }
    }
}
