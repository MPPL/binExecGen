from dataclasses import dataclass
from typing import Any
from copy import deepcopy
from typing_extensions import Self

def __bytes_assignment(data: bytes, index: int, value: int) -> bytes:
    ret: bytearray = bytearray(data)
    ret[index] = value
    return bytes(ret)

def reverse_endian(data: bytes) -> bytes:
    return bytes(reversed(bytearray(data)))

class StaticBytes:
    data: bytes
    lenght: int

    def __init__(self, lenght: int, data: bytes = b'', to_little: bool = False) -> None:
        if data != b'':
            if  len(data) < lenght:
                raise ValueError
            self.lenght = lenght
            self.data = bytes(bytearray(data)[-lenght:])
            if to_little:
                self.data = bytes(reversed(self.data.lstrip(b'\x00'))) + bytes(self.lenght - len(self.data.lstrip(b'\x00')))
        else:
            self.lenght = lenght
            self.data = bytes(self.lenght)
    
    def __call__(self, *args: Any, **kwds: Any) -> Any:
        if not isinstance(args[0], (str, bytes, bytearray, list, tuple, StaticBytes)):
            raise TypeError
        elif isinstance(args[0], (list, tuple)) and not isinstance(args[0][0], int):
            raise TypeError
        elif isinstance(args[0], StaticBytes):
            if args[0].lenght < self.lenght:
                raise ValueError
            val = args[0].data
        elif len(args[0]) < self.lenght:
            raise ValueError
        elif isinstance(args[0], str):
            val: bytes = args[0].encode("utf-8")
        else:
            val: bytes = bytes(args[0])
        self.data = bytes(bytearray(val)[-self.lenght:])
    
    def __reversed__(self) -> StaticBytes:
        copy: StaticBytes = deepcopy(self)
        copy.data = bytes(reversed(copy.data))
        return copy
    
    def as_addr64(self) -> Addr64:
        return Addr64(self.data)
    
    def as_vaddr64(self) -> vAddr64:
        return vAddr64(Addr64(self.data))
    
    def as_paddr64(self) -> pAddr64:
        return pAddr64(Addr64(self.data))

    def force_little(self) -> None:
        self.data = bytes(reversed(self.data.lstrip(b'\x00'))) + bytes(self.lenght - len(self.data.lstrip(b'\x00')))

    def force_big(self) -> None:
        self.data = bytes(self.lenght - len(self.data.rstrip(b'\x00'))) + bytes(reversed(self.data.rstrip(b'\x00')))

class Addr64:
    addr: StaticBytes

    def __init__(self, addr: bytes) -> None:
        self.addr = StaticBytes(8)
        self.addr(addr)

@dataclass
class Addr32:
    addr: StaticBytes = StaticBytes(4)

    def __init__(self, addr: bytes) -> None:
        self.addr(addr)

@dataclass
class vAddr64:
    addr: Addr64

@dataclass
class pAddr64:
    addr: Addr64

