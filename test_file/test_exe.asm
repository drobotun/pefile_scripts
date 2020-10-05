format PE64 GUI
include 'win64ax.inc'

.data
    text db 'Программа для проверки pefile_scripts.py', 0
    caption db 'Test file', 0

.code
start:
    invoke MessageBox, 0, text, caption, 0
    invoke ExitProcess, 0
.end start