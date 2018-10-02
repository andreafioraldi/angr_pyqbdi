import pyqbdi
from angr_qbdi import VMShot, init

init("localhost") # connect to rpyc classic srv

from angrdbg import *
    

def bpCB(vm, gpr, fpr, data):
    # wrapper around the angr state returned by VMShot
    s = StateManager(VMShot(vm))
    
    print " >> symbolizing 0x%x : 100" % gpr.rax
    
    # the argv[0] string address is in rax
    s.sim(s["rax"], 100)
    m = s.simulation_manager()
    
    print " >> starting exploration..."
    
    m.explore(find=0x400602, # find: 0000000000400602 mov     edi, offset aCorrectThatIsT ; "Correct! that is the secret key!"
        avoid=0x40060E) # avoid: 000000000040060E mov     edi, offset aIMSorryThatSTh ; "I'm sorry, that's the wrong secret key!"
    
    if len(m.found) > 0:
        print " >> valid state found"
    else:
        print " >> valid state not found"
        return
    
    s.to_dbg(m.found[0]) # write concretized solution to memory
    
    # print concretized solution
    print " >> solution:"
    c = s.concretize(m.found[0])
    print "0x%x : 100 = %s" % (list(c)[0], repr(c[list(c)[0]]))
    
    return pyqbdi.CONTINUE


def pyqbdipreload_on_run(vm, start, stop):
    # add hook on 00000000004005F9 call    verify
    v = vm.addCodeAddrCB(0x4005F9, pyqbdi.PREINST, bpCB, None)
    vm.run(start, stop)


