# PatchedCLRLoader
PatchedCLRLoader is a fork of PatchlessCLRLoader to load .NET assembly and direct the output to mailslot.This is just a practise for me to write some malware . And I have also tried to write my own code with hwbp to test in crowdstrike but do not know why it does not have any output after executing assembly, so I write this(patching) loader to bypass amsi and etw for assembly
<ul>
  <li>RC4 encryption payload</li>
  <li>Patching CLR and ETW bypass via direct Syscalls</li>
</ul>


Since patching AmsiScanBuffer in amsi.dll and Eventwrite in ntdll.dll does not work in new windows defender version (e.g. win11). Therefore, I tried to patch the AmsiScanBuffer in clr.dll and NtTraceEvent instead.

<b>Why patching clr work？</b></br>
Reference: <https://practicalsecurityanalytics.com/new-amsi-bypss-technique-modifying-clr-dll-in-memory/>
![](images/callstack.png)

when you are loading assembly ,AmsiScanBuffer will be called in amsi.dll , the AmsiScanBuffer function will then call AmsiScan in clr.dll .

![](images/presudocode.png)
In AmsiScan function, the AV /EDR will only identified the contents as malicious when the global_pAmsiContext is not equal to 0 in AmsiScan function in clr.dll. So we may find the address of the AmsiScanBuffer param in GetProcAddress, and simply patch it to zero or non-exist function buffer. Then, the Amsi can be easily bypassed. 

# Usage

<b>RC4 Encrypt Payload</b>

```
python RC4encrypt.py -i <c# assembly> -o <output> -k <Encryption Key>
```
![](images/RC4.png)

# AV / EDR Testing Result

| AV/EDR Product | Execute |
| ------ | ------ |
| Palo Alto Cortex XDR | :white_check_mark: |
| Sophos  | :white_check_mark: |
| MDE | :white_check_mark: |
| CrowdStrike | :white_check_mark: |

# Credits
InlineExecute-Assembly - <https://github.com/anthemtotheego/InlineExecute-Assembly> </br>
PatchlessCLRLoader - <https://github.com/VoldeSec/PatchlessCLRLoader></br>
<https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell></br>
<https://github.com/Mr-Un1k0d3r/AMSI-ETW-Patch>
