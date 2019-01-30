## Bleak 

[![Build status](https://ci.appveyor.com/api/projects/status/f19i6yj053atkn4h?svg=true)](https://ci.appveyor.com/project/Akaion/bleak)

A Windows native DLL injection library written in C# that supports several methods of injection.

----

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

### Features

* x86 injection from an x64 process

----

### Installation

* Download and install Bleak using [NuGet](https://www.nuget.org/packages/Bleak)
* Compile as AnyCPU

----

### Usage

Any method can be overloaded with a process id instead of a process name

You also have the option to overload the dll path with a byte array representing the dll

#### Injection Methods

All injection methods follow the same syntax described below

```csharp
using Bleak;

var injector = new Injector();

// Inject a dll into a process using the CreateRemoteThread method

injector.CreateRemoteThread("processName", "pathToDll");
```

#### Extension Methods

All extension methods follow the same syntax described below

```csharp
using Bleak;

var injector = new Injector();

// Erase the PE headers of a dll loaded in the process

injector.EraseHeaders("processName", "pathToDll");
```

----

### Contributing

Pull requests are welcome. 

For large changes, please open an issue first to discuss what you would like to add.
