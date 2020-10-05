format PE64 GUI
include 'win64ax.inc'

.data
    test_data db 0x34

.code
start:
   mov eax, test_data
.end start
