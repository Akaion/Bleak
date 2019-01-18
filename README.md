## Bleak 

[![Build status](https://ci.appveyor.com/api/projects/status/f19i6yj053atkn4h?svg=true)](https://ci.appveyor.com/project/Akaion/bleak)

A Windows native DLL injection library written in C# that supports several methods of injection.

### Supported Methods

* CreateRemoteThread
* ManualMap
* NtCreateThreadEx
* QueueUserAPC
* RtlCreateUserThread
* SetThreadContext (Thread Hijack)
* ZwCreateThreadEx

### Extensions

* Eject DLL
* Erase PE Headers
* Randomise PE Headers
* Unlink DLL From PEB

### Installation

* Download and install Bleak using [NuGet](https://www.nuget.org/packages/Bleak)

### Usage

You can overload any method with the processes id instead of the processes name

#### Injection Methods

All injection methods follow the same syntax as described below

```csharp
using Bleak;

var injector = new Injector();

// Inject a dll into a process using the CreateRemoteThread method

injector.CreateRemoteThread("processName", "pathToDll");
```

#### Extension Methods

All extension methods follow the same syntax as described below

```csharp
using Bleak;

var injector = new Injector();

// Erase the PE Headers of a dll loaded into a process

injector.EraseHeaders("processName", "pathToDll");
```

### Contributing
Pull requests are welcome. 

For large changes, please open an issue first to discuss what you would like to add.
