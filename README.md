# arena

# Pre-Requisites:
  1. WinDbg ()
  2. Pykd ()
  3. pefile ()
  
  
 # Usage:
    arena.bat file_name.exe
    
    Important: put the APIs you want to hook in apis_list.txt file (line separated)
 # Output:
    A json formatted log file containing APIs parameters will be generated in <root dir>results/<md5 of file>_log.json
