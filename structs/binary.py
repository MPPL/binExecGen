from dataclasses import dataclass
from typing import Any, Union
from copy import deepcopy
from typing_extensions import Self
from binary.tools.convert import BTLEndian, LTBEndian, extend as bitExtend, shorten as bitShorten
from binary.tools.string import nice_hex

def __bytes_assignment(data: bytes, index: int, value: int) -> bytes:
    ret: bytearray = bytearray(data)
    ret[index] = value
    return bytes(ret)

def reverse_endian(data: bytes) -> bytes:
    return bytes(reversed(bytearray(data)))

class StaticBytes:
    data: bytes
    lenght: int
    is_little: bool

    def __init__(self, lenght: int, data: bytes = b'', to_little: bool = False) -> None:
        '''
            |data| is always assumed to be 'big' endian
        '''
        
        self.is_little = to_little
        if data != b'':
            if  len(data) < lenght:
                raise ValueError(f"len of data -> {len(data)} | expected -> {lenght}")
            self.lenght = lenght
            self.data = bytes(bytearray(data)[-lenght:])
            if to_little:
                self.data = bytes(reversed(self.data.lstrip(b'\x00'))) + bytes(self.lenght - len(self.data.lstrip(b'\x00')))
        else:
            self.lenght = lenght
            self.data = bytes(self.lenght)
    
    def __call__(self, data: Union[int, str, bytes, bytearray, list, tuple, StaticBytes]) -> Any:
        '''
            |args[0]| is always assumed to be 'big' endian
        '''

        if not isinstance(data, (str, bytes, bytearray, list, tuple, StaticBytes)):
            raise TypeError
        
        elif isinstance(data, int):
            self.data = data.to_bytes(self.lenght, 'little' if self.is_little else 'big')

        elif isinstance(data, (list, tuple)):
            if not isinstance(data[0], int):
                raise TypeError
            else:
                self.data = data[0].to_bytes(self.lenght, 'little' if self.is_little else 'big')
        elif isinstance(data, StaticBytes):
            if data.lenght < self.lenght:
                raise ValueError
            val = data.data
            if data.lenght != self.lenght:
                if data.lenght < self.lenght:
                    val = bitExtend(val, self.lenght - data.lenght, data.is_little)
                else:
                    val = bitShorten(val, data.lenght - self.lenght, data.is_little)
            if data.is_little != self.is_little:
                if data.is_little:
                    val = LTBEndian(val)
                else:
                    val = BTLEndian(val)
            self.data = val
        elif len(data) < self.lenght:
            raise ValueError
        elif isinstance(data, str):
            val: bytes = data.encode("utf-8")
            if len(val) > self.lenght:
                raise ValueError
            if self.is_little:
                self.data = BTLEndian(val)
            else:
                self.data = val
        else:
            val = bytes(data)
            if self.is_little:
                self.data = BTLEndian(val)
            else:
                self.data = val
    
    def __reversed__(self) -> StaticBytes:
        copy: StaticBytes = deepcopy(self)
        copy.is_little = not self.is_little
        if self.is_little:
            copy.data = LTBEndian(copy.data)
        else:
            copy.data = BTLEndian(copy.data)
        return copy
    
    def as_addr64(self) -> Addr64:
        return Addr64(self.data)
    
    def as_int(self) -> int:
        return int.from_bytes(self.data, 'little' if self.is_little else 'big')

    def convert_to_little(self) -> None:
        if self.is_little:
            return
        self.data = BTLEndian(self.data)
        self.is_little = True

    def convert_to_big(self) -> None:
        if not self.is_little:
            return
        self.data = LTBEndian(self.data)
        self.is_little = False

class Addr64:
    addr: StaticBytes

    def __init__(self, addr: bytes | StaticBytes) -> None:
        if isinstance(addr, bytes):
            self.addr = StaticBytes(8)
            self.addr(addr)
        elif isinstance(addr, StaticBytes):
            if addr.lenght != 8:
                raise ValueError(f"Lenght of addr in Addr64 contstructor is wrong, should be 8 bytes")
            self.addr = addr
        else:
            raise TypeError("Wrong type of data provided to Addr64 constructor")

@dataclass
class Addr32:

    def __init__(self, addr: bytes) -> None:
        if isinstance(addr, bytes):
            self.addr = StaticBytes(4)
            self.addr(addr)
        elif isinstance(addr, StaticBytes):
            if addr.lenght != 4:
                raise ValueError(f"Lenght of addr in Addr32 contstructor is wrong, should be 4 bytes")
            self.addr = addr
        else:
            raise TypeError("Wrong type of data provided to Addr32 constructor")

@dataclass
class Symbol:
    add_vaddr: bool
    data: bytes
    offset: int
    lenght: int

    def __str__(self) -> str:
        return f"Symbol(add_vaddr = |{self.add_vaddr}|, data = |{nice_hex(self.data)}|, offset = |{self.offset}|, lenght = |{self.lenght}|)"