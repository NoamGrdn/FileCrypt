---
layout: post
title:  "Preface"
date:   2025-10-17 15:40:07 +0300
categories: jekyll update
---

### Story time (If uninterseted, skip straight to [DriverEntry](#driverentry))

As part of the final year of our B.Sc. in Computer Science at the College of Management Academic Studies, we had to choose a _“specialization”_ - a program in which students get to choose more practice-oriented courses and do work that is a bit closer to the real tech industry.

The three of us, seeking a challenge and learn and experience new things that we don’t get to do in our jobs (each one at their own), chose Cyber Security out of the available options as our specialization.
In addition to the courses of each specialization, all students take a year-long ‘Final Project’ course, in which they are divided into groups and tasked with doing a project in the field of their specialty for the entire final year.

This, together with the facts that:
The three of us wanted to do a sort of research and/or development at a lower software level, whether it involved some kind of exploitation or reverse engineering. Fast forward to the day of the _Project Ideas Presentation_, our then-idea, which involved video game exploitation, was fairly brutally rejected (and rightfully so - there wasn’t anything unique about it, and it added very little value). We were left without the slightest idea of what to do, and now we are almost behind schedule for submission. At the end of a very long brainstorming weekend, one of us, while going through literally every single official Microsoft driver on his personal Windows machine, encountered a driver named FileCrypt. After a googling (and a bit of AI prompting) session, only very basic and generic metadata information, alongside users troubleshooting BSOD issues, was available online. No official Microsoft documentation, no explicit mentions in articles, in-fact, zero information. But it looked liked something we might be interested in:
1. The driver was only 94 KB in size, not very big, and suitable for reverse engineering in the time we have.
2. From its file description, which reads: “Windows sandboxing and encryption filter”, the driver had something to do with encryption - very fitting for our project requirement.

We discussed the matter among the three of us, while tossing the sys file into Ghidra, to get a very basic assessment of the magnitude of the situation - we came up with a new project idea: Reverse engineer this driver to the fullest extent to figure out what it does and why it exists. 
We couldn’t set our goal to be “exploitation of the driver” for two main reasons: First, there is no guarantee that there are vulnerabilities in this driver; and more importantly, the project must have a concrete end goal that can be achieved within the timeframe of the academic year. Plus, the fact that we have no experience in reverse engineering and absolutely none 

in exploitation at even normal user-mode applications, we wanted to avoid goals like those entirely.
After formulating the idea, we contacted our supervisor, Dr. Gal Badishi. He generously (and quite unexpectedly to us), agreed to have a video call with us on the weekend. This gave us a chance to bounce back with a fresh idea and make the schedule on the assignment.

At the call, Dr. Badishi said he had liked our idea given the following circumstances:
- We had no prior reverse engineering experience 
- The driver has absolutely no public documentation or information about it online
- The “product” of the project is an open-source work that can potentially benefit the wider security community

With those considerations, he gave us a green light.

Now, after what we are sure is an extremely interesting story for everyone, and without further delay, let’s get into the technical details.

When we found the driver and honed in on our idea, we started reading driver documentation and articles on the official [Microsoft documentation website][kernel-mode-driver-architecture-design-guide]. We did this to gain a better understanding of what we would see inside the driver’s code, and because at one point, we wanted to write a driver ourselves to get a glimpse of how the development process for such a thing works. We very quickly realized that we need to understand what we are to focus on because, to absolutely no one's surprise, the documentation is massive.

Before going into the driver’s decompiled code, we played around with Visual Studio’s driver template projects, specifically “Kernel Mode Driver (KMDF)” to get to know the basic data types we are going to be working with, jumping around different header files, getting a general idea of how source code for Windows drivers look and trying to relate it all to the documentation we were reading at the same time.

Then, we set up [Ghidra][Ghidra] with the driver’s basic PDB files, which, fortunately, were made public by Microsoft. So now, into the code!
Not quite. We are a team of three, and we must be able to work in parallel. With regular git, it would have been very simple: create a branch, commit to it, and merge. Unfortunately, Ghidra does not integrate well with git because it creates files that are difficult to merge and practically unusable with a git environment. However, the NSA has devised a solution. Ghidra comes with a runnable service called _Ghidra Server_, which allows multiple people working on the same reversing project to synchronize their work. Unlike git, Ghidra Server does not have an equivalent to GitHub, so we had to host our own instance of Ghidra Server.

Now, let us begin with the driver’s code: We began examining the driver’s decompiled code, starting with the `DriverEntry`.
At this point, we wanted to see how what we have read in the docs, combined with what we see in the driver template project, compares with the decompiled code. 
Because this is not a _device_ driver, at first glance, we did not find what we were looking for; however, we did encounter filter-driver functions, such as `FltRegisterFilter`, `FltStartFiltering`, and `FltUnregisterFilter`. We then knew that what we were looking at, was a [minifilter driver][about-file-system-filter-drivers]. That sent us back to the docs to read more about filter drivers - what they are, how they operate, and how they interact with the rest of the operating system. While reading Microsoft’s documentation, we came across a [GitHub repository][windows-driver-samples] that contains a variety of example drivers, including a comprehensive set of minifilter drivers. [This driver][scanner-driver], named _Scanner_, caught our attention in particular because, judging from its description, it performs a task roughly in the same area as what our driver does.
This repo turned out to be very useful for referencing Windows API calls and how they look in actual source code.

Back to Ghidra, we wanted to start renaming and retyping the most obvious variables and function parameters, starting, for example, with the arguments of the DriverEntry. 

# DriverEntry

```
void DriverEntry(
   ushort* param_1,
   ushort* param_2
)
```

[part-one-link]: {% post_url 2025-10-17-welcome-to-jekyll %}
[kernel-mode-driver-architecture-design-guide]: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/
[ghidra]: https://github.com/NationalSecurityAgency/ghidra
[about-file-system-filter-drivers]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/about-file-system-filter-drivers
[windows-driver-samples]: https://github.com/microsoft/Windows-driver-samples/
[scanner-driver]: https://github.com/microsoft/Windows-driver-samples/tree/main/filesys/miniFilter/scanner