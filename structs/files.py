from dataclasses import dataclass
from structs.binary import Addr64, StaticBytes, Symbol
from binary.tools.convert import fit_in_align
from binary.tools.string import nice_hex

class Header:

    data: bytes

    def __init__(self, data: bytes) -> None:
        self.data = data
    
    def __len__(self) -> int:
        return len(self.data)
    
    def as_bytes(self) -> bytes:
        return self.data

class DotCode:

    data: bytes
    index: list[int]
    max_len: int
    offset: int = 0
    vaddr: Addr64
    align: int

    def __init__(self, max_len: int, align: int, offset: int = 0, vaddr: Addr64 = Addr64(StaticBytes(8))):
        self.data = bytes(0)
        self.index = []
        self.max_len = max_len
        self.offset = offset
        self.vaddr = vaddr
        self.align = align
    
    def set_offset(self, offset: int):
        self.offset = offset
    
    def set_vaddr(self, vaddr: Addr64):
        self.vaddr = vaddr
    
    def set_align(self, align: int):
        self.align = align

    def add_entry(self, data: bytes):
        if len(data) + len(self.data) > self.max_len:
            raise BufferError
        self.index.append(len(self.data))
        self.data += data
    
    def __len__(self) -> int:
        return len(self.data)
    
    def as_bytes(self) -> bytes:
        ret: bytearray = bytearray(fit_in_align(len(self.data), self.align))
        ret[:len(self.data)] = self.data
        return bytes(ret)

class DotData:

    data: bytes
    index: list[int]
    max_len: int
    offset: int = 0
    vaddr: Addr64
    align: int

    def __init__(self, max_len: int, align: int, offset: int = 0, vaddr: Addr64 = Addr64(StaticBytes(8))):
        self.data = bytes(0)
        self.index = []
        self.max_len = max_len
        self.offset = offset
        self.vaddr = vaddr
        self.align = align
    
    def set_offset(self, offset: int):
        self.offset = offset
    
    def set_vaddr(self, vaddr: Addr64):
        self.vaddr = vaddr
    
    def set_align(self, align: int):
        self.align = align
    
    def add_entry(self, data: bytes):
        if len(data) + len(self.data) > self.max_len:
            raise BufferError
        self.index.append(len(self.data))
        self.data += data
    
    def __len__(self) -> int:
        return len(self.data)
    
    def as_bytes(self) -> bytes:
        ret: bytearray = bytearray(fit_in_align(len(self.data), self.align))
        ret[:len(self.data)] = self.data
        return bytes(ret)

class ExecFile:

    header: Header
    code: DotCode
    text: DotData

    symbols: list[Symbol]

    is_little: bool = False

    def __init__(self, header: Header, code: DotCode, text: DotData, is_little: bool = False) -> None:
        self.header = header
        self.code = code
        self.text = text
        self.symbols = []
        self.is_little = is_little
    
    def as_bytes(self) -> bytes:
        return self.header.as_bytes() + self.code.as_bytes() + self.text.as_bytes()
    
    def __len__(self) -> int:
        return len(self.header.data + self.code.data + self.text.data)
    
    def set_is_little(self, val: bool):
        self.is_little = val 
    
    def append_exec(self, data: Symbol):
        self.symbols.append(data)
    
    def append_data(self, data: bytes):
        self.text.add_entry(data)
    
    def get_symbol_len(self) -> int:
        return sum([len(x.data) for x in self.symbols])

    def resolve_symbols(self):
        for y, x in enumerate(self.symbols):
            print(x.add_vaddr)
            if x.add_vaddr:
                n = x.data[x.offset:x.offset+x.lenght]
                tmp = bytearray(x.data)
                tmp[x.offset:x.offset+x.lenght] = (self.text.vaddr.addr.as_int() + int.from_bytes(n, 'little' if self.is_little else 'big')).to_bytes(x.lenght, 'little' if self.is_little else 'big')
                print(nice_hex(n) , "|", nice_hex(tmp[x.offset:x.offset+x.lenght]))
                self.symbols[y].data = tmp

    def apply_symbols(self):
        print("\n".join([str(x) for x in self.symbols]))
        for x in self.symbols:
            self.code.add_entry(x.data)