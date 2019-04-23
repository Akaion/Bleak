using Bleak.Injection.Objects;

namespace Bleak.Injection.Interfaces
{
    internal interface IInjectionExtension
    {
        bool Call(InjectionProperties injectionProperties);
    }
}
