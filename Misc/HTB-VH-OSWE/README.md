# HTB and Vulnhub: An OSWE Approach

### Preface

I hope that this post would be beneficial to anyone preparing for OSWE. It's not an AWAE review, nor an OSWE Exam review. It's my personal answer to the question:
>Is it possible to prepare for the OSWE Exam with HTB or Vulnhub?

### Why?

While preparing for an exam, it's common use among us to try and get any useful information or additional practice to ensure us the best probabilities to achive success. Nobody likes to fail. While I was preparing for the various Offensive Security certification exams I saw quite a good number of attempts to compare OSCP/OSCE/OSWE with other courses or pre-built machines on HTB and Vulnhub. To have a clearer understanding of what I am talking about you can take a look at the very good Excel Sheet done by NetSecFocus at: 

[NetSecFocus Trophy Room](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=665299979)

### Overview

While I honestly think that playing HTB and similar is very useful in general, I'm not sure about recommending it for certs like OSCE and OSWE. Why? It's very simple, OS.E certs are not meant to be purely black box, especially OSWE.
While in OSCE you can debug the service you are testing, in OSWE you can both debug and access the code of the application you're testing.

Indeed, the main focus of the AWAE course is finding more subtle vulnerabilities using source code analysis techniques. The learning objective is to understand how to review a big or huge codebase in a timeboxed window. With that in mind, trying to exploit HTB machines, which are completely unaccessible without exploiting them in the first place, it's almost a non sense activity (for OSWE-specific preparation, of course). VulnHub can be seen as a better option, as the underlying filesystem can be accessed without prior exploitation of the VM, but the main problem is that usually web applications used in VulnHub machines are challenging as long as their code is uknown, and do not provide the level of complexity that real web applications have.

That said, let's start taking a look at the machines proposed by NetSecFocus.

#### HTB

##### Falafel and Popcorn

* Challenges
    - Bypass File Upload Restrictions 
* Source code analysis requirments
    - Nope

##### Vault

* Challenges
    - Enumeration
    - Port forwarding
    - File sharing with netcat
    - Use of PGP 
* Source code analysis requirments
    - Nope

##### Blocky

* Challenges
    - Use JD-GUI
    - Adapt CVEs Exploits
    - Vulnerability Chaining
    - Webshells
    - Use of PGP 
* Source code analysis requirments
    - Locate credentials within Jar file (1 file)
    - Decompile JAR files
* 2 methods to gain root, the preferred for me is:
    - Use the creds to access phpmyadmin
    - change user and password
    - Access Wordpress and upload a crafted plugin
    - Escalate from www-data to root

##### Arkham

* Challenges
    - Use cryptsetup to dump/decrypt LUKS disks
    - Read Web Application's Documentation
    - Know how to use crypto utility to encrypt a payload
    - Know how to use ysoserial to generate an RCE payload via insecure deserialsiation
* Source code analysis requirments
    - Documentation reading

##### Summary

Wrapping up the above info, I would say that only Arkham (up to user shell) and Blocky (also up to user shell) are worth for OSWE preparation.

For anyone else, they are fairly funny machines (mostly vault and arkham).

### VulnHub

##### Pipe

* Challenges
    - Know how to exploit PHP insecure deserialisation to achieve RCE
* Source code analysis requirements
    - Source Code Analysis of 3 PHP files (Boringly simple)
* OSWE Style Walkthrough:
    - [Pipe](reviews/vulnhub/pipe)

##### Raven2

* Challenges
    - Detect missing input validation
    - Debug PHP app via code augmentation [big word, small task]
* Source code analysis requirements
    - Source Code Analysis of PHPMailer (Important files: 2)
* OSWE Style Walkthrough:
    - [Raven](reviews/vulnhub/raven2)

##### Homeless

* Challenges
    - Know a bit of hashing functions
* Source code analysis requirements
    - Source Code Analysis of 3-4 PHP files
* OSWE Style Walkthrough:
    - [Homeless](reviews/vulnhub/homeless)

##### Ted

* Challenges
    - Know how to exploit PHP Local File Inclusion to achieve RCE
* Source code analysis requirements
    - Source Code Analysis of a few PHP files
* OSWE Style Walkthrough:
    - [Ted](reviews/vulnhub/ted)

##### Flick2

* Challenges
    - Understand how APIs work
    - Know how to decompile/recompile an APK
    - A bit of enumeration
* Source code analysis requirements
    - Little APK decompiled code analysis 
* OSWE Style Walkthrough:
    - [Flick2](reviews/vulnhub/flick2)
    - Additional Exercise at the end

### Who I am

I'm a just another-security-passionate with an insatiable hunger for knowledge.