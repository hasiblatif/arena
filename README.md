## ARENA (Automated Reverse EngiNeering and Analysis System)

An automated reverse engineering system which leverages WinDbg (Windows Debugger) and Pykd (python based debugger). It reports the called APIs with parameters into JSON formatted log, hence very useful for automation. It also bypasses most popular anti-debugging / anti-reversing tricks as well.

## Installation:

### Pre-Requisites:
  1. WinDbg -> http://download.microsoft.com/download/A/6/A/A6AC035D-DA3F-4F0C-ADA4-37C8E5D34E3D/setup/WinSDKDebuggingTools/dbg_x86.msi
  2. Pykd -> https://pykd.codeplex.com
  3. pefile (pip install pefile)
  
 #### Supported Platform: 
      Windows, 32 bit only (tested on Windows 7 x86_64). Some tweaks are needed to enable for 64 bit binaries.
  
 ### Usage:
    arena.bat <file_name.exe>
    
    (Please update the path in arena.bat)
    
    
    
 ### Output:
    A json formatted log file containing APIs parameters will be generated in
    <root dir>results/<md5 of file>_log.json
    

#### Which APIs are Hooked?
    It's entirely upto you. The APIs you want to hook should be put in "apis_list.txt" (line separated). 
    APIs which you want to explicitly exclude can be optionally put into white_listed_apis.txt 
    if you hook the IAT table as well but current implementation does bot need that as it ignores IAT.
    
    Note: APIs will be reported only when they are called from hooked executable's code
    
#### What about Anti-Debugging Tricks?
    More than fifteen ant-debugging / anti-reversing tricks have been bypassed :)    

Happy reversing :)
    
