# Bleak 

[![Build status](https://ci.appveyor.com/api/projects/status/f19i6yj053atkn4h?svg=true)](https://ci.appveyor.com/project/Akaion/bleak)

A Windows native DLL injection library written in C# that supports several methods of injection.

## Supported Methods

* CreateRemoteThread
* ManualMap
* NtCreateThreadEx
* QueueUserAPC
* RtlCreateUserThread
* SetThreadContext (Thread Hijack)
* ZwCreateThreadEx

## Extensions

* Eject DLL
* Erase PE Headers
* Randomise PE Headers

## Installation

* Download and install Bleak using [NuGet](https://www.nuget.org/packages/Bleak)

## Usage

You can also overload any method with a process id instead of a process name

```csharp
using Bleak;

var injector = new Injector();

// Inject using the CreateRemoteThread method

injector.CreateRemoteThread("pathToDll", "processName");

// Erase the PE Headers

injector.EraseHeaders("pathToDll", "processName");
```

## Contributing
Pull requests are welcome. 

For large changes, please open an issue first to discuss what you would like to add.
