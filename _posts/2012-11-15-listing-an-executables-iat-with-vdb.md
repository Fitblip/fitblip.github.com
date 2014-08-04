---
layout: post
title: "Listing an executable's IAT with VDB"
description: ""
category: 
tags: []
---
{% include JB/setup %}
While researching a unified debugging solution for [Sulley](https://github.com/OpenRCE/sulley) I poked [@pedramamini](https://twitter.com/pedramamini) who recommended I look into [@invisig0th's](https://twitter.com/invisig0th) VDB/Vtrace.

Let me start off by saying *holy crap*

VDB aims to be a unified debugging platform, letting you climb up a layer of abstraction for windows/osx/linux (and talking to [@at1as](https://twitter.com/at1as), it looks like there's some preliminary ARM support!), and debug processes the same way across architectures. That's exactly what I was looking for.

I'm a big fan of learning by diving face first into things, so I decided to whip up a quick [IAT](http://en.wikipedia.org/wiki/Portable_Executable#Import_Table) (Import Address Table) parser. It doesn't work on packed executables or do anything fancy, simply dumps every library and function an executable is looking for. 

Code ahoy!

{% highlight python %}
# Standard modules
import platform
import sys
import re

# Setup variables
cur_arch = platform.architecture()[0]
vdb_path = "C:\\old_downloads\\vdb_20120806"
run_prog = "C:\\windows\\system32\\calc.exe"
#run_prog = "C:\\Program Files\\7-Zip\\7zFM.exe"

# If we define our vdb path, insert it into sys.path
if vdb_path: sys.path.insert(1,vdb_path)

# Import vtrace and PE
import vtrace
import PE

# Import the current archtype only. 
# Only 64-bit python can debug 64 bit apps. 
if cur_arch == "32bit":
    from envi.archs import i386 as arch
else:
    from envi.archs import amd64 as arch

def parsePE(exe = run_prog):
    """
    Checks our PE for it's architecture, and 
    """
    # Parse our PE
    pe_parsed = PE.peFromFileName(exe)

    # Get our 'Machine' field -> Tells us the architecture it 
    # was compiled for
    pe_arch = pe_parsed.IMAGE_NT_HEADERS.FileHeader.Machine

    # If our platform arch != our PE header arch, exit out. 
    # PE.IMAGE_FILE_MACHINE_I386  == 0x0000014c [ 332 ] == 32 bit
    # PE.IMAGE_FILE_MACHINE_AMD64 == 0x00008664 [34404] == 64 bit
    if pe_arch == PE.IMAGE_FILE_MACHINE_I386 and cur_arch != "32bit":
        print "This won't work! Debugging 32-bit executable in 64-bit python"
        sys.exit(1)
    elif pe_arch == PE.IMAGE_FILE_MACHINE_AMD64 and cur_arch != "64bit":
        print "This won't work! Debugging 64-bit executable in 32-bit python"
        sys.exit(1)

    return pe_parsed

# Parse out our PE information
p = parsePE()

# Execute our trace and get our base address
trace = vtrace.getTrace()
trace.execute(run_prog)

# Load our library base addresses
libs = trace.getMeta("LibraryBases")
# Find our PE base address
base = libs[re.findall('^.*\\\\(\w+).exe',run_prog.lower())[0]]

# Set up our exports dictionary to hold all the children functions for each DLL
exports = {}
for ord_num, dll_name, func_name in p.getImports():
    exports.setdefault(dll_name,[]).append((hex(base+ord_num),func_name))

# Print everything out!
for dll in exports:
    print dll.lower()
    for export in exports[dll]:
        print "\t" + export[0] + " - " + export[1]
{% endhighlight%}

Looks daunting, right? That's how a lot of VDB code turns out, you're just doing complicated things with binary files and memory, so it can't really be avoided.

<!--excerpt-->

Looking at the first section:

{% highlight python %}
# Standard modules
import platform
import sys
import re

# Setup variables
cur_arch = platform.architecture()[0]
vdb_path = "C:\\old_downloads\\vdb_20120806"
run_prog = "C:\\windows\\system32\\calc.exe"
#run_prog = "C:\\Program Files\\7-Zip\\7zFM.exe"

# If we define our vdb path, insert it into sys.path
if vdb_path: sys.path.insert(1,vdb_path)

# Import vtrace and PE
import vtrace
import PE

# Import the current archtype only. 
# Only 64-bit python can debug 64 bit apps. 
if cur_arch == "32bit":
    from envi.archs import i386 as arch
else:
    from envi.archs import amd64 as arch

{% endhighlight%}

Here we import some basic modules, set some option variables, and import the rest of the VDB stuff. Not much to say, the code is pretty self-explanatory (and commented).

Let's move onto the second chunk:

{% highlight python %}
def parsePE(exe = run_prog):
    """
    Checks our PE for it's architecture, and 
    """
    # Parse our PE
    pe_parsed = PE.peFromFileName(exe)

    # Get our 'Machine' field -> Tells us the architecture it 
    # was compiled for
    pe_arch = pe_parsed.IMAGE_NT_HEADERS.FileHeader.Machine

    # If our platform arch != our PE header arch, exit out. 
    # PE.IMAGE_FILE_MACHINE_I386  == 0x0000014c [ 332 ] == 32 bit
    # PE.IMAGE_FILE_MACHINE_AMD64 == 0x00008664 [34404] == 64 bit
    if pe_arch == PE.IMAGE_FILE_MACHINE_I386 and cur_arch != "32bit":
        print "This won't work! Debugging 32-bit executable in 64-bit python"
        sys.exit(1)
    elif pe_arch == PE.IMAGE_FILE_MACHINE_AMD64 and cur_arch != "64bit":
        print "This won't work! Debugging 64-bit executable in 32-bit python"
        sys.exit(1)

    return pe_parsed
{% endhighlight%}

First thing we do is load our executable into a PE class, which parses our a whole bunch of good, juicy information for us.

Remember kids - IPython is always your friend when exploring new pieces of code.

{% highlight bash %}
> ipython -i vtrace_ex.py
-- SNIP -- 
In [1]: p.<TAB>
p.IMAGE_DOS_HEADER    p.getMaxRva           p.inmem               p.readAtRva
p.IMAGE_NT_HEADERS    p.getPdataEntries     p.parseExports        p.readPointerAtOffset
p.checkRva            p.getRelocations      p.parseImports        p.readPointerAtRva
p.fd                  p.getResourceDef      p.parseLoadConfig     p.readResource
p.getDataDirectory    p.getResources        p.parseRelocations    p.readRvaFormat
p.getDllName          p.getSectionByName    p.parseResources      p.readStringAtRva
p.getExportName       p.getSections         p.parseSections       p.readStructAtOffset
p.getExports          p.getVS_VERSIONINFO   p.pe32p               p.readStructAtRva
p.getForwarders       p.high_bit_mask       p.psize               p.rvaToOffset
p.getImports          p.imports             p.readAtOffset        p.sections
{% endhighlight%}

There are a **lot** of interesting things here, but what we're focused on here is the [IMAGE_NT_HEADERS](http://msdn.microsoft.com/en-us/library/windows/desktop/ms680336(v=vs.85).aspx), which has a few fields, namely **Signature**, **FileHeader**, and **OptionalHeader**. By calling `p.IMAGE_NT_HEADERS.tree()` we can get a good overview of the information stored there.

**Signature section (should always be "PE\x00\x00")**

{% highlight bash %}
In [3]: print p.IMAGE_NT_HEADERS.tree()<ENTER>
00000000 (248) IMAGE_NT_HEADERS: IMAGE_NT_HEADERS
00000000 (04)   Signature: 50450000
{% endhighlight%}

**FileHeader section**

{% highlight bash %}
00000004 (20)   FileHeader: IMAGE_FILE_HEADER
00000004 (02)     Machine: 0x0000014c (332)
00000006 (02)     NumberOfSections: 0x00000004 (4)
00000008 (04)     TimeDateStamp: 0x4a5bc622 (1247528482)
0000000c (04)     PointerToSymbolTable: 0x00000000 (0)
00000010 (04)     NumberOfSymbols: 0x00000000 (0)
00000014 (02)     SizeOfOptionalHeader: 0x000000e0 (224)
00000016 (02)     Ccharacteristics: 0x00000102 (258)
{% endhighlight%}	

**OptionalHeader section**

{% highlight bash %}
00000018 (224)   OptionalHeader: IMAGE_OPTIONAL_HEADER
00000018 (02)     Magic: 0b01
0000001a (01)     MajorLinkerVersion: 0x00000009 (9)
0000001b (01)     MinorLinkerVersion: 0x00000000 (0)
0000001c (04)     SizeOfCode: 0x00052e00 (339456)
00000020 (04)     SizeOfInitializedData: 0x0006a600 (435712)
00000024 (04)     SizeOfUninitializedData: 0x00000000 (0)
00000028 (04)     AddressOfEntryPoint: 0x00009768 (38760)
0000002c (04)     BaseOfCode: 0x00001000 (4096)
00000030 (04)     BaseOfData: 0x00052000 (335872)
00000034 (04)     ImageBase: 0x01000000 (16777216)
00000038 (04)     SectionAlignment: 0x00001000 (4096)
0000003c (04)     FileAlignment: 0x00000200 (512)
00000040 (02)     MajorOperatingSystemVersion: 0x00000006 (6)
00000042 (02)     MinorOperatingSystemVersion: 0x00000001 (1)
00000044 (02)     MajorImageVersion: 0x00000006 (6)
00000046 (02)     MinorImageVersion: 0x00000001 (1)
00000048 (02)     MajorSubsystemVersion: 0x00000006 (6)
0000004a (02)     MinorSubsystemVersion: 0x00000001 (1)
0000004c (04)     Win32VersionValue: 0x00000000 (0)
00000050 (04)     SizeOfImage: 0x000c0000 (786432)
00000054 (04)     SizeOfHeaders: 0x00000400 (1024)
00000058 (04)     CheckSum: 0x000cd612 (841234)
0000005c (02)     Subsystem: 0x00000002 (2)
0000005e (02)     DllCharacteristics: 0x00008140 (33088)
00000060 (04)     SizeOfStackReserve: 0x00040000 (262144)
00000064 (04)     SizeOfStackCommit: 0x00002000 (8192)
00000068 (04)     SizeOfHeapReserve: 0x00100000 (1048576)
0000006c (04)     SizeOfHeapCommit: 0x00001000 (4096)
00000070 (04)     LoaderFlags: 0x00000000 (0)
00000074 (04)     NumberOfRvaAndSizes: 0x00000010 (16)
00000078 (128)     DataDirectory: VArray
00000078 (08)       0: IMAGE_DATA_DIRECTORY
00000078 (04)         VirtualAddress: 0x00000000 (0)
0000007c (04)         Size: 0x00000000 (0)
--SNIP--
{% endhighlight%}	

So the field we're interested in is the [FileHeader](http://msdn.microsoft.com/en-us/library/windows/desktop/ms680313(v=vs.85).aspx) -> [Machine field](http://msdn.microsoft.com/en-us/library/windows/desktop/ms680313(v=vs.85).aspx#code-snippet-1). This will give us the architecture our executable was compiled to run on, and with pretty much anything in the wonderful world of Windows, it's in a binary format.

Thankfully visi has provided us with some handy reference attributes for the PE module. They're pretty self-explanatory, but just to re-iterate.

{% highlight python %}
PE.IMAGE_FILE_MACHINE_I386  == 0x0000014c [ 332 ] == 32 bit
PE.IMAGE_FILE_MACHINE_AMD64 == 0x00008664 [34404] == 64 bit
{% endhighlight%}	

Cool beans. Let's move onto the code that actually parses out our executable's [IAT](http://en.wikipedia.org/wiki/Portable_Executable#Import_Table).

{% highlight python %}
# Parse out our PE information
p = parsePE()

# Execute our trace and get our base address
trace = vtrace.getTrace()
trace.execute(run_prog)

# Load our library base addresses
libs = trace.getMeta("LibraryBases")
# Find our PE base address
base = libs[re.findall('^.*\\\\(\w+).exe',run_prog.lower())[0]]

# Set up our exports dictionary to hold all the children functions for each DLL
exports = {}
for ord_num, dll_name, func_name in p.getImports():
    exports.setdefault(dll_name,[]).append((hex(base+ord_num),func_name))

# Print everything out!
for dll in exports:
    print dll.lower()
    for export in exports[dll]:
        print "\t" + export[0] + " - " + export[1]
{% endhighlight%}	

When using the vtrace module, you pretty much always follow this convention. You can set breakpoints, or parameters to set breakpoints for you, then you call `trace.run()`, which is equivalent to a continue in $(your debugger of choice).

The `getMeta()` function is something that basically allows you to query the state of affairs going on with your trace handler (as far as I understand it). In our case we call it with "LibraryBases" which gives us our library names and their offsets. We could have also called "LibraryPaths", which would've given us a similar data structure with the full path to our libraries, but I chose to write a terrible looking regular expression to just chomp out our executable name to find it's base address.

Now that we have our program's base address though, we basically just need to get a list of the imports from our PE module. Super simple. The exports dictionary is populated with the dll name as the key, and a value array of tuples in the form `(calculated address, name)` for each function it imports.

It may be simpler to see the data itself, but just know we calculate the offset relative to our executable's base address.	

{% highlight bash %}
In [36]: exports<ENTER>
--SNIP--
'ntdll.dll': [('0xf7112cL', 'WinSqmAddToStreamEx'),
 ('0xf71130L', 'WinSqmIncrementDWORD'),
 ('0xf71134L', 'WinSqmAddToStream'),
 ('0xf71138L', 'NtQueryLicenseValue'),
 ('0xf7113cL', 'RtlInitUnicodeString')],
'ole32.dll': [('0xf710f4L', 'CoInitialize'),
 ('0xf710f8L', 'CoUninitialize'),
 ('0xf710fcL', 'CoCreateInstance')]}
{% endhighlight%}	

So there you have it. Fairly straight-forward code to dump all the imports for your executable's IAT! I cranked this out in a single night while drinking beer and relaxing, so needless to say - this tool makes for some extremely fast prototyping of awesome debugger stuff!

Looking into the ridiculously extensive sourcecode for VDB, I can only conclude that [@invisig0th's](https://twitter.com/invisig0th) and [@at1as](https://twitter.com/at1as) are simply smart people, and are just swimming in 0-days.

<img class='post-image' src="{{ site.url }}/assets/img/visi-0day.png">