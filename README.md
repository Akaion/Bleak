# Simple Injection

A DLL injection library written in C# that supports several methods of process injection.

## Supported Methods

* CreateRemoteThread
* QueueUserAPC
* SetThreadContext (Thread Hijack)

## Installation

* Clone this repository
* Compile the project as AnyCPU
* Add a reference to Simple-Injection.dll to your project

## Usage

```csharp
using Simple_Injection;

var injector = new Injector();

injector.CreateRemoteThread("pathToDll", "processName");
```

## Contributing
Pull requests are welcome. 

For major changes, such as new injection methods, please open an issue first to discuss what you would like to add.
