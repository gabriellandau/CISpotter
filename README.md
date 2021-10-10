# Code Integrity Violation Spotter

See [this blog post](https://www.elastic.co/blog) for more information.

Windows normally performs Protected Process Light code integrity checks during `NtCreateSection(SEC_IMAGE)`.  
CI Spotter adds similar checks during `NtMapViewOfSection`, preventing CI bypasses through mechanisms such as [KnownDlls cache poisoning](https://www.elastic.co/blog/protecting-windows-protected-processes).

**This is a proof of concept. Use it at your own risk.**

## Building and running it

1. Compile the CISpotter.sln with Visual Studio 2019.
2. Enable [Test Signing](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option).
3. Register and start the service:
```
sc create CISpotter type= kernel start= demand binpath= %CD%\CISpotter.sys
sc start CISpotter
```
