## TL;DR

With the general term "AV Evasion" we refer to the set of techniques that allows an attacker to execute arbitrary code 
into a system, bypassing all controls that should prevent her from doing it.

## Introduction

One of the key areas during a Red Team or penetration test is how to evade security controls such as an intrusion detection system (IDS), 
antivirus (AV) software and EDR solutions.

This is not always a trivial task, and it's becoming more and more difficult to accomplish in a sensible, standard way.
Most of the current techniques requires developing custom droppers or implants in order to bypass these controls.

In the following posts, I'm going to present a few among the methods that I commonly use in order to accomplish this, 
and a set of tools I've created to ease this process:

* [Chameleon: Born from a Chimera](./BornFromAChimera/)
* [The path to code execution in the era of EDR, Next-Gen AVs, and AMSI](./CodeExeNewDotNet/)
* [SysWhispers is dead, long live SysWhispers!](NoSysWhisper/)
* [From Process Injection to Function Hijacking](FromInjectionToHijacking/)
* [SilentMoonwalk: Implementing a fully dynamic Call Stack Spoofer](StackSpoofing/)

[Back to Red Teaming](../)

[Back to Home](https://klezvirus.github.io/)