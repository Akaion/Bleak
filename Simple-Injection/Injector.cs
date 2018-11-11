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

        public bool EraseHeaders(string dllPath, string processName)
        {
            return MEraseHeaders.Erase(dllPath, processName);
        }

        public bool RandomiseHeaders(string dllPath, string processName)
        {
            return MRandomiseHeaders.Randomise(dllPath, processName);
        }
    }
}
