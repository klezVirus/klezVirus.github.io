## TL;DR

The term "Lateral movement" refers to the the set of techniques that allows an attacker to acquire further access into a network, after gaining initial access. The attacker, after gaining access to the network, maintains ongoing access by moving through the compromised environment and obtaining increased privileges using various tools.

## Introduction

Often, during a red team engagement or internal penetration test, a tester requires to move laterally in the compromised domain, to extend his access and permissions up to the designated target.

 >Lateral movement is the process of moving from one compromised host to another. 

Usually, lateral movement includes three main steps:
* Internal Reconnaissance
* Privilege Escalation and dumping of Credentials Hashes and Kerberos Tickets
* Gain access on a remote (lateral) target
 
In the following posts, are presented a few among the methods commonly used to accomplish this, and a set of C# tools created to ease this process:

* [CheeseDCOM: Abusing DCOM technology for Lateral Movement](./LateralMovementDCOM/)
* [TODO: CheeseExec: Abusing the Service Manager for lateral Movement](./)
* [CheesePS: Abusing the PowerShell Remoting for lateral Movement](./LateralMovementPSRemoting/)

[Back to Red Teaming](../)

[Back to Home](https://klezvirus.github.io/)


[1]: https://github.com/klezVirus/CheeseTools