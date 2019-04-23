using Bleak.Injection.Objects;

namespace Bleak.Injection.Interfaces
{
    internal interface IInjectionMethod
    {
        bool Call(InjectionProperties injectionProperties);
    }
}
