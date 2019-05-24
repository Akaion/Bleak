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

* Optional randomise DLL name
* WOW64 and x64 injection

----

### Installation

* Download and install Bleak using [NuGet](https://www.nuget.org/packages/Bleak)

----

### Getting Started

After installing Bleak, you will want to ensure that your project is being compiled under AnyCPU or x64. This will ensure that you are able to inject into both WOW64 and x64 processes from the same project.

----

### Useage

The example below describes a basic implementation of the library.

```csharp
using Bleak;

var randomiseDllName = true;

var injector = new Injector(InjectionMethod.CreateThread, "processName", "dllPath", randomiseDllName);

// Inject the DLL into the process using the CreateThread method

var dllBaseAddress = injector.InjectDll();

// Hide the injected DLL from the PEB

injector.HideFromPeb();

// Eject the DLL from the process

injector.EjectDll();

injector.Dispose();
```

----

### Overloads

Several overloads exist in this library.

The first of these allows you to use a process ID instead of a process name.

```csharp
var injector = new Injector(InjectionMethod.CreateThread, processId, "dllPath");
```

The second of these allows you to use a byte array representing a DLL instead of a DLL path.

```csharp
var injector = new Injector(InjectionMethod.CreateThread, "processName", dllBytes);
```
----

### Caveats

* Injecting with a byte array will result in the provided DLL being written to disk in the temporary folder, unless the method of injection is ManualMap.

* WOW64 ManualMap relies on a PDB being present for ntdll.dll, and so, the first time this method is used with a WOW64 process, a PDB for ntdll.dll will be downloaded and cached in the temporary folder. Note that anytime your system updates, a new PDB version may need to be downloaded and re-cached in the temporary folder. This process make take a few seconds depending on your connection speed.

----

### Contributing

Pull requests are welcome. 

For large changes, please open an issue first to discuss what you would like to add.
