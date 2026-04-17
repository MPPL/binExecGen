from dataclasses import dataclass
from structs.binary import Addr64, StaticBytes

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

    def __init__(self, max_len: int, offset: int, vaddr: Addr64):
        self.data = bytes(0)
        self.index = []
        self.max_len = max_len
        self.offset = offset
        self.vaddr = vaddr
    
    def set_offset(self, offset: int):
        self.offset = offset

    def add_entry(self, data: bytes):
        if len(data) + len(self.data) > self.max_len:
            raise BufferError
        self.index.append(len(self.data))
        self.data += data
    
    def __len__(self) -> int:
        return len(self.data)
    
    def as_bytes(self) -> bytes:
        ret: bytearray = bytearray(self.max_len)
        ret[0:len(self.data)] = self.data
        return bytes(ret)

class DotData:

    data: bytes
    index: list[int]
    max_len: int
    offset: int = 0
    vaddr: Addr64

    def __init__(self, max_len: int, offset: int, vaddr: Addr64):
        self.data = bytes(0)
        self.index = []
        self.max_len = max_len
        self.offset = offset
        self.vaddr = vaddr
    
    def set_offset(self, offset: int):
        self.offset = offset
    
    def add_entry(self, data: bytes):
        if len(data) + len(self.data) > self.max_len:
            raise BufferError
        self.index.append(len(self.data))
        self.data += data
    
    def __len__(self) -> int:
        return len(self.data)
    
    def as_bytes(self) -> bytes:
        ret: bytearray = bytearray(self.max_len)
        ret[0:len(self.data)] = self.data
        return bytes(ret)

class ExecFile:

    header: Header
    code: DotCode
    text: DotData

    def __init__(self, header: Header, code: DotCode, text: DotData) -> None:
        self.header = header
        self.code = code
        self.text = text
    
    def as_bytes(self) -> bytes:
        return self.header.as_bytes() + self.code.as_bytes() + self.text.as_bytes()
    
    def __len__(self) -> int:
        return len(self.header.data + self.code.data + self.text.data)
    
    def append_exec(self, data: bytes):
        self.code.add_entry(data)
    
    def append_data(self, data: bytes):
        self.text.add_entry(data)

def nice_hex(data: bytes) -> str:
    return f"{" ".join([ f"{hex(x).replace('0x', ''):0>2}" for x in data]) }"