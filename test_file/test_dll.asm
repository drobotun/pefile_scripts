format   PE GUI DLL
include 'win32ax.inc'

.data
    text db 'Программа для проверки pefile_scripts.py', 0
    caption db 'Test DLL', 0
 
.code
start:
    mov eax, 1
    ret
 

proc TestFunction
    invoke MessageBox, 0, text, caption, 0
    ret
endp
 
.end start
 

section '.edata' export data readable
export  'test_dll.dll',\
         TestFunction, 'TestFunction'
section '.reloc' fixups data discardable
