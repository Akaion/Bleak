using Simple_Injection.Methods;

namespace Simple_Injection
{
    public class Injector
    {
        public bool CreateRemoteThread(string dllPath, string processName)
        {
            return MCreateRemoteThread.Inject(dllPath, processName);
        }

        public bool QueueUserAPC(string dllPath, string processName)
        {
            return MQueueUserAPC.Inject(dllPath, processName);
        }
        
        public bool RtlCreateUserThread(string dllPath, string processName)
        {
            return MRtlCreateUserThread.Inject(dllPath, processName);
        }
        
        public bool SetThreadContext(string dllPath, string processName)
        {
            return MSetThreadContext.Inject(dllPath, processName);
        }
    }
}
