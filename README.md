# About 

Titan is a User Defined Reflective DLL ( URDLL ) that uses a combination of techniques to achieve initial execution and maintain shell stability for Cobalt Strike in a modern endpoint-deteciton and response heavy environment. 

Titan is designed to work specifically with Cobalt Strike and with Cobalt Strike alone. It could be ported to other frameworks, but likely is pointless in doing so.

## Table of Contents

 - [Techniques](#Techniques)
     - [Memory Evasion](#Memory-Evasion-Obfuscate-and-Sleep)
     - [DNS over HTTP(s)](#DNS-Now-with-DNS-over-HTTPs)
     - [Single Threaded](#Single-Thread)
     - [System Calls!](#Redirect-To-System-Calls)
 - [Setup](#Setup)

## Techniques

### Memory Evasion: Obfuscate and Sleep

Titan implements a basic x86_64 memory evasion hook that hides the traces of its implant in memory with the help user-created timer callbacks, a technique popularized by NightHawk and implemented publicly by the user [Paul](https://twitter.com/c5pider) whom published the project under the name [Ekko](https://github.com/Cracked5pider/Ekko). However, both implementation have a few caveats and race conditions that lead to it being unstable.

The latest version supports multiple sessions being spawned within the same process due to the creation of a new thread pool for each Beacon. It no longer breaks the host process's original queue if it is using one.

It currently encryptes when Beacon waits for jobs to complete, while it is sleeping, and while SMB pipes are awaiting a connection, writing to a pipe, or reading from a named pipe to avoid detection when transfering data over the network.

| Beacon                | Obfuscated In Memory |
|-----------------------|----------------------|
| windows/reverse_https | TRUE                 |
| windows/reverse_dns   | TRUE                 |
| windows/smb           | TRUE                 |
| windows/tcp           | FALSE                |

### DNS: Now with DNS over HTTP(s)!

DNS beacons recieved a completed overhall that allowed them to send their traffic over a more secure DNS over HTTP(s) provider that is hardcoded within the hook code itself. Each and every request will be seen sent to those providers, masking the original DNS name with ease. If you wish that your traffic be sent over the original DNS protocol, then you can disable this hook.

### Single Thread

Cobalt is largely single threaded on its own, but Titan forces it to be entirely single threaded. Unfortunately, this breaks some of the internal functionality such as Powershell-based commands 
at the cost of operational security. Largely, this should not break a majority of the functionality you're using, but will break some.

### Redirect To System Calls

Some functions that involve remote process interaction are redirected to System Calls using a mapping of KnownDLLs for x86/x64/WOW64. It avoids some detections that SentinelOne/CrowdStrike implement with their inline hooks.

## Setup

To start utilizing Titan, you will need to install `nasm`, `make`, `python3`, the [pefile module for python](https://github.com/erocarrera/pefile) and Mingw-w64. You will need the mingw-w64 compilers from musl.cc, which is available here for [x86_64-w64-mingw32-cross](https://musl.cc/x86_64-w64-mingw32-cross.tgz), and [i686-w64-mingw32-cross](https://musl.cc/i686-w64-mingw32-cross.tgz) to compile the code, as the ones available in your package managers is not updated to the latest versions. Once you've setup your compilers in the PATH, and installed the above packages, you can start compiling the source code!

Example steps to download the cross-compilers and add them to your PATH:

```
# cd /root/tools
# wget https://musl.cc/x86_64-w64-mingw32-cross.tgz
# tar -xvf x86_64-w64-mingw32-cross.tgz
# cd x86_64-w64-mingw32-cross/bin
# export PATH=$(pwd):$PATH
# cd /root/tools
# wget https://musl.cc/i686-w64-mingw32-cross.tgz
# tar -xvzf i686-w64-mingw32-cross.tgz
# cd i686-w64-mingw32-cross/bin
# export PATH=$(pwd):$PATH
```

A sample output is shown below

 ```shell=/bin/bash
devvm:~/projects/kit/titan $ make
/root/tools/i686-w64-mingw32-cross/bin/../lib/gcc/i686-w64-mingw32/11.2.1/../../../../i686-w64-mingw32/bin/ld: Titan.x86.exe:.text: section below image base
/root/tools/i686-w64-mingw32-cross/bin/../lib/gcc/i686-w64-mingw32/11.2.1/../../../../i686-w64-mingw32/bin/ld: Titan.x86.exe:.edata: section below image base
/root/tools/x86_64-w64-mingw32-cross/bin/../lib/gcc/x86_64-w64-mingw32/11.2.1/../../../../x86_64-w64-mingw32/bin/ld: Titan.x64.exe:.text: section below image base
/root/tools/x86_64-w64-mingw32-cross/bin/../lib/gcc/x86_64-w64-mingw32/11.2.1/../../../../x86_64-w64-mingw32/bin/ld: Titan.x64.exe:.edata: section below image base
```

Success! You've successfully compiled the binary files needed to utilize it. To begin using it, include the `Titan.cna` into your Aggressor Scripts `Cobalt Strike > Script Manager`. Once you've imported the aggressor script into Cobalt, you can begin exporting an `raw` artifact to use with Shelter or embedding into your own artifact kit!

![](https://i.imgur.com/sI5Quif.png)
