
import struct
import pefile

from ctypes import *

from pydbg import *
from pydbg.defines import *

#Global Variables
# arq = Variable holding EXE to be analyzed
arq = r"C:\main.exe"
MemBps = []
HwBps = []
glAddress = None
glDoCrc = False

#Debugger
dbg = None

#PE Format
pe = pefile.PE(arq) #Open
EP = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint #EntryPoint
CS = pe.OPTIONAL_HEADER.ImageBase + pe.sections[0].VirtualAddress #VA of Code Section
CSSize = pe.sections[0].Misc #Size of Code Section
pe.close() #Close

def NoneDbg(dbg):
    dbg = None

def Func(dbg):

    current = EP
    global MemBps

    while current != (EP+CSSize):
        stackFrame = 0
        paddr = dbg.read_process_memory(current, 4)
        addr  = struct.unpack("<L", paddr)[0]

        for a in paddr:
            if ord(a) == 0x55:
                stackFrame = 1
            elif (ord(a) == 0x89 and stackFrame == 1):
                stackFrame = 2
            elif (ord(a) == 0xE5 and stackFrame == 2):
                stackFrame = 3
            elif (ord(a) == 0x83 and stackFrame == 3):
                if current == 0x40138C:
                        print "[*] Reading address %X" % current
                        print "[**] Current MemBps size %d " % len(MemBps)
                        print ""
                if current != EP:
                    MemBps.append(current)

        current = current+4

    #Cleaning EP breakpoint
    dbg.bp_del(dbg.context.Eip)

    for c in MemBps:
        dbg.bp_set(c, description=c, restore=False, handler=None)

    dbg.terminate_process(exit_code=0, method="terminateprocess")

    return DBG_CONTINUE

def hw(dbg):

    global glAddress, glDoCrc, HwBps

    print ""
    print "\t[*] Hited at %X" % dbg.context.Eip
    print "\t[**] Break accessing %X" % glAddress

    #address was hited and logged to posterior analysis
    HwBps.append(glAddress)

    #delete breakpoint hited
    dbg.bp_del_hw(glAddress)

    #address of new breakpoint (sequential reading)
    glAddress = glAddress+1

    print "\t[**] Next hit %X" % glAddress

    #setting new breakpoint
    dbg.bp_set_hw(glAddress, 1, HW_ACCESS, "HWBREAK", True, hw)

    if len(HwBps) >= 10:
        print ""
        print ">> DO CRC CHECKING! <<"
        print ""
        glDoCrc = True
        dbg.terminate_process()

    return DBG_CONTINUE

def main():

    global dbg, glAddress, HwBps, MemBps

    try:
        '''
            # Acquiring information #
        '''
        #Initialize
        dbg = pydbg()
        dbg.load(arq)

        #Callback handles
        dbg.set_callback(EXIT_PROCESS_DEBUG_EVENT, NoneDbg)

        #Break on Entry Point
        dbg.bp_set(EP,description="EntryPoint",restore=True,handler=Func)

        #Run it
        dbg.debug_set_process_kill_on_exit(True)
        dbg.run()

    finally:
        for c in MemBps:
            #Check if global variable glDoCrc is still False
            if glDoCrc:
                quit()
            #Global variable of address to HWBP
            glAddress = c

            #New list of sequential read using HWBP
            HwBps = []

            #Screen print, advising about HWBP code block
            print ""
            print "-> Set HWBP in %X" % glAddress

            '''
                begin Debugger code block
            '''
            dbg = pydbg()
            dbg.load(arq)
            dbg.set_callback(EXIT_PROCESS_DEBUG_EVENT, NoneDbg)
            dbg.bp_del_hw_all()
            #First HWBP to sequential read
            dbg.bp_set_hw(glAddress, 1, HW_ACCESS, "HWBREAK", True, hw)
            dbg.run()
            '''
                end Debugger code block
            '''

        #If CRC check is found, then the script will already be dead
        print ""
        print ">> CRC CHECKING NOT FOUND <<"
        print ""

if __name__ == "__main__":
    main()