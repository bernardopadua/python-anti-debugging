# Automation of anti-debugging CRC cheking technique

This technique have the goal of not allowing the executable to be analyzed inside an anti-debugging tool. 
Isn't a complex technique but it's pretty functional. My goal with this is to help the community of developers and analysts. 
This code have a good example on how this technique works and how to detect it.

Fun and learning. Any question just let me know, I would be glad to help.

## main.c

  Simple program that do the CRC checking.

  References::
  http://automationwiki.com/index.php/CRC-16-CCITT

## main.py

  This is the code responsable to analyze the executable. I used some libraries to help me on the process.
  
  * pydbg: It's pretty like a debugger, but only coding way. Very complete!
    * https://github.com/OpenRCE/pydbg
  * pefile: This is responsable to get the PE (Portable executable) information.
    * https://github.com/erocarrera/pefile
    
  Any question about the code just let me know, I would be glad to help.