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

----

### Installation

* Download and install Bleak using [NuGet](https://www.nuget.org/packages/Bleak)

----

### Usage

Injection and Extension methods follow the same syntax as described below

**Note** that any method can be overloaded with a process id instead of a process name

```csharp
using Bleak;

var injector = new Injector();

// Inject a dll into a process using the CreateRemoteThread method

injector.CreateRemoteThread("processName", "pathToDll");

// Erase the PE headers of a dll loaded in the process

injector.EraseHeaders("processName", "pathToDll");
```
You also have the option to overload the dll path with a byte array representing the dll

```csharp
using Bleak;

var injector = new Injector();

// Inject a dll into a process using the CreateRemoteThread method

injector.CreateRemoteThread("processName", dllBytes);

// Erase the PE headers of a dll loaded in the process

injector.EraseHeaders("processName", dllBytes);
```
----

### Contributing
Pull requests are welcome. 

For large changes, please open an issue first to discuss what you would like to add.
