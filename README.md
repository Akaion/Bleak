# Bleak

A Windows native DLL injection library written in C# that supports several methods of injection.

## Supported Methods

* CreateRemoteThread
* ManualMap (x86 only)
* NtCreateThreadEx
* QueueUserAPC
* RtlCreateUserThread
* SetThreadContext (Thread Hijack)
* ZwCreateThreadEx

## Features

* Erase PE Headers
* Randomise PE Headers

## Installation

* Download and install Bleak using [NuGet](https://www.nuget.org/packages/Bleak/1.0.0)

## Usage

```csharp
using Bleak;

var injector = new Injector();

// Inject using the CreateRemoteThread method

injector.CreateRemoteThread("pathToDll", "processName");

// Erase the PE Headers

injector.EraseHeaders("pathToDll", "processName")
```

## Contributing
Pull requests are welcome. 

For large changes, please open an issue first to discuss what you would like to add.
