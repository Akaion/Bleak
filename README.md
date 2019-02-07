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
* SetThreadContext
* ZwCreateThreadEx

### Extensions

* Eject DLL
* Erase PE Headers
* Randomise PE Headers
* Unlink DLL From PEB

### Features

* x86 and x64 injection

----

### Installation

* Download and install Bleak using [NuGet](https://www.nuget.org/packages/Bleak)

----

### Usage Example

The example below describes a basic implementation of the library.

```csharp
using Bleak;

var injector = new Injector();

// Inject a dll into a process using the CreateRemoteThread method

injector.CreateRemoteThread("processName", "pathToDll");

// Erase the PE headers of a dll loaded in the process

injector.EraseHeaders("processName", "pathToDll");
```
Full documentation of the library, including examples can be found here (documentation currently being created) 

----

### Contributing

Pull requests are welcome. 

For large changes, please open an issue first to discuss what you would like to add.
