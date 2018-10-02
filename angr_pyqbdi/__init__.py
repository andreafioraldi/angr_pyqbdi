import pyqbdi
import struct
import rpyc
import sys

conn = None

SEG_PROT_R = 4
SEG_PROT_W = 2
SEG_PROT_X = 1

# implements the methods defined in the abstract class angrdbg.Debugger
class AngrQBDI(object):
    def __init__(self, vm, mod):
        self.name = "AngrQBDI"
        self.vm = vm
        self.mod = mod
        self.maps = pyqbdi.getCurrentProcessMaps()
    
    #-------------------------------------
    def before_stateshot(self):
        pass
    def after_stateshot(self, state):
        pass

    #-------------------------------------
    def is_active(self):
        return True
    
    #-------------------------------------
    def input_file(self):
        return sys.argv[0]
    
    def image_base(self):
        return self.maps[0].range[0]
    
    #-------------------------------------
    def get_byte(self, addr):
        try:
            return ord(pyqbdi.readMemory(addr, 1))
        except BaseException:
            return None

    def get_word(self, addr):
        try:
            return struct.unpack("<H", pyqbdi.readMemory(addr, 2))[0]
        except BaseException:
            return None

    def get_dword(self, addr):
        try:
            return struct.unpack("<I", pyqbdi.readMemory(addr, 4))[0]
        except BaseException:
            return None

    def get_qword(self, addr):
        try:
            return struct.unpack("<Q", pyqbdi.readMemory(addr, 8))[0]
        except BaseException:
            return None

    def get_bytes(self, addr, size):
        try:
            return str(pyqbdi.readMemory(addr, size))
        except BaseException:
            return None

    def put_byte(self, addr, value):
        pyqbdi.writeMemory(addr, chr(value))

    def put_word(self, addr, value):
        pyqbdi.writeMemory(addr, struct.pack("<H", value))

    def put_dword(self, addr, value):
        pyqbdi.writeMemory(addr, struct.pack("<I", value))

    def put_qword(self, addr, value):
        pyqbdi.writeMemoryy(addr, struct.pack("<Q", value))

    def put_bytes(self, addr, value):
        pyqbdi.writeMemory(addr, value)
    
    #-------------------------------------
    def get_reg(self, name):
        gpr = self.vm.getGPRState()
        if name == "efl": name = "eflags"
        return getattr(gpr, name)

    def set_reg(self, name, value):
        gpr = self.vm.getGPRState()
        if name == "efl": name = "eflags"
        setattr(gpr, name, value)
        self.vm.setGPRState(gpr)
    
    #-------------------------------------
    def wait_ready(self):
        return
    def refresh_memory(self):
        return
    
    #-------------------------------------
    def seg_by_name(self, name):
        s = filter(lambda x: x.name == name, self.maps)
        if len(s) == 0: return None
        s = s[0]
        perms = 0
        perms |= SEG_PROT_R if s.permission  & pyqbdi.PF_READ else 0
        perms |= SEG_PROT_W if s.permission  & pyqbdi.PF_WRITE else 0
        perms |= SEG_PROT_X if s.permission  & pyqbdi.PF_EXEC else 0
        return self.mod.Segment(name, s.range[0], s.range[1], s.permission)
    
    def seg_by_addr(self, addr):
        s = filter(lambda x: addr >= x.range[0] and addr < x.range[1], self.maps)
        if len(s) == 0: return None
        s = s[0]
        perms = 0
        perms |= SEG_PROT_R if s.permission  & pyqbdi.PF_READ else 0
        perms |= SEG_PROT_W if s.permission  & pyqbdi.PF_WRITE else 0
        perms |= SEG_PROT_X if s.permission  & pyqbdi.PF_EXEC else 0
        return self.mod.Segment(s.name, s.range[0], s.range[1], s.permission)

    def get_got(self): #return tuple(start_addr, end_addr)
        s = filter(lambda x: x.name == ".got.plt", self.mod.load_project().loader.main_object.sections)[0]
        return (s.vaddr, s.vaddr + s.memsize)
    
    def get_plt(self): #return tuple(start_addr, end_addr)
        s = filter(lambda x: x.name == ".plt", self.mod.load_project().loader.main_object.sections)[0]
        return (s.vaddr, s.vaddr + s.memsize)
    
    #-------------------------------------
    def resolve_name(self, name): #return None on fail
        return None


def register_vm(vm):
    conn.modules.angrdbg.register_debugger(AngrQBDI(vm, conn.modules.angrdbg))


# transfer the current vm state into an angr state
def VMShot(vm, **kwargs):
    conn.modules.angrdbg.register_debugger(AngrQBDI(vm, conn.modules.angrdbg))
    return conn.modules.angrdbg.StateShot(sync_brk=False, **kwargs)


def init(host, port=18812):
    global conn
    conn = rpyc.classic.connect(host, port)
    conn.execute("import angr, cle, claripy, angrdbg")
    conn.execute("import logging; logging.getLogger().setLevel(logging.ERROR)")
    sys.modules["angrdbg"] = conn.modules.angrdbg
    sys.modules["angr"] = conn.modules.angr
    sys.modules["cle"] = conn.modules.cle
    sys.modules["claripy"] = conn.modules.claripy


