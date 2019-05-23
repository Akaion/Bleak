## Bleak 

[![Build status](https://ci.appveyor.com/api/projects/status/wp76wa0oe8robs3c?svg=true)](https://ci.appveyor.com/project/Akaion/bleak)

A Windows native DLL injection library written in C# that supports several methods of injection.

----

### Injection Methods

* CreateThread
* HijackThread
* ManualMap

### Injection Extensions

* EjectDll
* HideDllFromPeb
* RandomiseDllHeaders

### Features

* x86 and x64 injection
* Optional randomise DLL name

----

### Installation

* Download and install Bleak using [NuGet](https://www.nuget.org/packages/Bleak)

----

### Usage Example

The example below describes a basic implementation of the library.

```csharp
using Bleak;

var injector = new Injector(InjectionMethod.CreateThread, "processName", "pathToDll");

// Inject the DLL into the process

injector.InjectDll();

// Hide the DLL from the PEB

injector.HideDllFromPeb();
```

Full documentation for the library can be found [here](https://akaion.github.io/repositories/bleak/bleak.html) 

----

### Contributing

Pull requests are welcome. 

For large changes, please open an issue first to discuss what you would like to add.
