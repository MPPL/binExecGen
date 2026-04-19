from enum import IntEnum
from structs.binary import Symbol

class REG(IntEnum):
    RAX = 0
    RCX = 1
    RDX = 2
    RBX = 3
    RBP = 4
    RSP = 5
    RSI = 6
    RDI = 7
    R8  = 8
    R9  = 9
    R10 = 10
    R11 = 11
    R12 = 12
    R13 = 13
    R14 = 14
    R15 = 15

class bit:
    val: bool

    def __init__(self, val: bool | int | str):
        if isinstance(val, bool):
            self.val = val
        elif isinstance(val, int):
            self.val = val != 0
        elif isinstance(val, str):
            self.val = val != "" or val != "0"
        else:
            raise TypeError
    
    def __call__(self) -> bool:
        return self.val
    
    def __int__(self) -> int:
        return int(self.val)

    def __str__(self) -> str:
        return str(self.__int__())
    
    def as_byte_at_index(self, index: int) -> bytes:
        if abs(index) > 7:
            raise ValueError(f"byte index should be in range |0-7| not |{abs(index)}|")
        return (self.__int__() * (2 ** abs(index))).to_bytes(1)


def gen_rex(is_64: bit = bit(0), Modmrm: bit = bit(0), Sibindex: bit = bit(0), Sibbase: bit = bit(0)) -> bytes:
    return (4 * 0x10 + int(is_64) * 0x08 + int(Modmrm) * 0x04 + int(Sibindex) * 0x02 + int(Sibbase) * 0x01).to_bytes(1)

def mov_r32_imm32(reg: REG, val: int, fix: bool = False) -> Symbol:
    return Symbol(fix, gen_rex(bit(1), bit(0), bit(0), bit(0)) + b'\xC7' + (192 + int(reg)).to_bytes(1) + val.to_bytes(4, 'little'),3,4)

def mov_r64_imm64(reg: REG, val: int, fix: bool = False) -> Symbol:
    if int(reg) > 7:
        raise ValueError(f"reg value |{reg}| outside of range |0-7|")
    return Symbol(fix, gen_rex(bit(1), bit(0), bit(0), bit(0)) + (184 + int(reg)).to_bytes(1) + val.to_bytes(8, 'little'),2,8)

def syscall() -> Symbol:
    return Symbol(False, b'\x0F\x05', 0,0)

def linux_exit_list() -> list[Symbol]:
    return [mov_r32_imm32(REG.RDI, 0), mov_r32_imm32(REG.RAX, 0x3C), syscall()]

def linux_exit_raw() -> Symbol:
    return Symbol(False, mov_r32_imm32(REG.RDI, 0).data + mov_r32_imm32(REG.RAX, 0x3C).data + syscall().data, 0,0)