from enum import IntEnum

class REG(IntEnum):
    RAX = 0
    RCX = 1
    RDX = 2
    RBX = 3
    RSI = 4
    RDI = 5
    RBP = 6
    RSP = 7
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

def mov_r32_imm32(reg: REG, val: int) -> bytes:
    return b''

def mov_r64_imm64(reg: REG, val: int) -> bytes:
    if int(reg) > 7:
        raise ValueError(f"reg value |{reg}| outside of range |0-7|")
    return gen_rex(bit(1), bit(0), bit(0), bit(0)) + (184 + int(reg)).to_bytes(1) + val.to_bytes(8, 'little')