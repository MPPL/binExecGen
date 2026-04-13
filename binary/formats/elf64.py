from structs.binary import Addr64, vAddr64, pAddr64, StaticBytes
from dataclasses import dataclass
from typing import Literal
from enum import Enum, IntFlag

ELF_IDENT: bytes = b'\x7F\x45\x4C\x46'
class ENUM_ELF_BYTES(Enum):
    ELF_32 = b'\x01'
    ELF_64 = b'\x02'

class ENUM_ELF_ENDIAN(Enum):
    ELF_LITTLE_ENDIAN = b'\x01'
    ELF_BIG_ENDIAN    = b'\x02'

ELF_VERSION_BYTE:   bytes = b'\x01'

class ENUM_ELF_ABI(Enum):
    ELF_ABI_SYSTEMV      = b'\x00'
    ELF_ABI_HP_UX        = b'\x01'
    ELF_ABI_NETBSD       = b'\x02'
    ELF_ABI_LINUX        = b'\x03'
    ELF_ABI_GNUHURD      = b'\x04'
    ELF_ABI_SOLARIS      = b'\x06'
    ELF_ABI_AIX          = b'\x07'
    ELF_ABI_IRIX         = b'\x08'
    ELF_ABI_FREEBSD      = b'\x09'
    ELF_ABI_TRU64        = b'\x0A'
    ELF_ABI_NOVELL       = b'\x0B'
    ELF_ABI_OPENBSD      = b'\x0C'
    ELF_ABI_OPENVMS      = b'\x0D'
    ELF_ABI_NONSTOP      = b'\x0E'
    ELF_ABI_AROS         = b'\x0F'
    ELF_ABI_FENIXOS      = b'\x10'
    ELF_ABI_NUXI         = b'\x11'
    ELF_ABI_OPENVOS      = b'\x12'
    ELF_ABI_DEFAULT      = ELF_ABI_LINUX

ELF_ABI_VERSION_LINUX:  bytes = b'\x00'
ELF_ABI_PADDING:        bytes = b'\x00\x00\x00\x00\x00\x00\x00'

class ENUM_ELF_TYPE(Enum):
    ELF_TYPE_NONE        = b'\x00\x00'
    ELF_TYPE_REL         = b'\x00\x01'
    ELF_TYPE_EXEC        = b'\x00\x02'
    ELF_TYPE_DYN         = b'\x00\x03'
    ELF_TYPE_CORE        = b'\x00\x04'
    ELF_TYPE_LOOS        = b'\xFE\x00'
    ELF_TYPE_HIOS        = b'\xFE\xFF'
    ELF_TYPE_LOPROC      = b'\xFF\x00'
    ELF_TYPE_HIPROC      = b'\xFF\xFF'


#UNFINISHED
class ENUM_ELF_ARCH(Enum):
    ELF_ARCH_NONE           = b'\x00\x00'
    ELF_ARCH_ATnT_WE_32100  = b'\x00\x01'
    ELF_ARCH_SPARC          = b'\x00\x02'
    ELF_ARCH_x86            = b'\x00\x03'
    ELF_ARCH_M68K           = b'\x00\x04'
    ELF_ARCH_M88K           = b'\x00\x05'
    ELF_ARCH_INTEL_MCU      = b'\x00\x06'
    ELF_ARCH_INTEL_80860    = b'\x00\x07'
    ELF_ARCH_MIPS           = b'\x00\x08'
    ELF_ARCH_IBM_370        = b'\x00\x09'
    ELF_ARCH_MIPS_RE3K_LE   = b'\x00\x0A'
    # ...
    ELF_ARCH_ARM            = b'\x00\x28'
    ELF_ARCH_x86_64         = b'\x00\x3E'
    ELF_ARCH_ARM64          = b'\x00\xB7'
    ELF_ARCH_RISC_V         = b'\x00\xF3'

    ELF_ARCH_DEFAULT        = ELF_ARCH_x86_64

ELF_2ND_VERSION_BYTE:   bytes = b'\x00\x00\x00\x01'


ELF_ENTRY_POINT:        bytes = bytes(8)

ELF_PH_TABLE_64:        bytes = b'\x00\x00\x00\x00\x00\x00\x00\x40'

ELF_SH_TABLE_64:        bytes = b'\x00\x00\x00\x00\x00\x00\x00\x40'

ELF_CPU_FLAGS:          bytes = b'\x00\x00'

ELF_HEADER_SIZE_64:     bytes = b'\x00\x40'

ELF_PH_TABLE_SIZE_64:   bytes = b'\x00\x00\x00\x40'

ELF_PH_TABLE_ENTRY_SIZE:bytes = b'\x00\x38'
ELF_PH_TABLE_ENTRIES:   bytes = b'\x00\x01'

ELF_SH_TABLE_ENTRY_SIZE:bytes = b'\x00\x40'
ELF_SH_TABLE_ENTRIES:   bytes = b'\x00\x00'
ELF_SH_TABLE_NAMES:     bytes = b'\x00\x00'

class ELF_PH_TYPE(Enum):
    PT_NULL     = b'\x00\x00\x00\x00\x00\x00\x00\x00'
    PT_LOAD     = b'\x00\x00\x00\x00\x00\x00\x00\x01'
    PT_DYNAMIC  = b'\x00\x00\x00\x00\x00\x00\x00\x02'
    PT_INTERP   = b'\x00\x00\x00\x00\x00\x00\x00\x03'
    PT_NOTE     = b'\x00\x00\x00\x00\x00\x00\x00\x04'
    PT_SHLIB    = b'\x00\x00\x00\x00\x00\x00\x00\x05'
    PT_PHDR     = b'\x00\x00\x00\x00\x00\x00\x00\x06'
    PT_TLS      = b'\x00\x00\x00\x00\x00\x00\x00\x07'
    PT_LOOS     = b'\x00\x00\x00\x00\x60\x00\x00\x00'
    PT_HIOS     = b'\x00\x00\x00\x00\x6F\xFF\xFF\xFF'
    PT_LOPROC   = b'\x00\x00\x00\x00\x70\x00\x00\x00'
    PT_HIPROC   = b'\x00\x00\x00\x00\x70\xFF\xFF\xFF'

class ELF_PH_FLAGS(IntFlag):
    EXEC = 1
    WRIT = 2
    READ = 4

ELF_DEFAULT_VIRTUAL_START = b'\x00\x00\x00\x00\x00\x40\x00\x00'


class ELF64_HEADER:
    MAGIC_BYTES:    StaticBytes = StaticBytes(4, ELF_IDENT)
    BITS:           StaticBytes = StaticBytes(1, ENUM_ELF_BYTES.ELF_64.value)
    ENDIANESS:      StaticBytes = StaticBytes(1, ENUM_ELF_ENDIAN.ELF_BIG_ENDIAN.value)
    VERSION:        StaticBytes = StaticBytes(1, ELF_VERSION_BYTE)
    ABI:            StaticBytes = StaticBytes(1)
    ABI_VERSION:    StaticBytes = StaticBytes(1)
    PADDING:        StaticBytes = StaticBytes(7)
    OBJECT_TYPE:    StaticBytes = StaticBytes(2)
    MACHINE:        StaticBytes = StaticBytes(2)
    VERSION2:       StaticBytes = StaticBytes(4, ELF_2ND_VERSION_BYTE)
    ENTRY_POINT:    vAddr64     = vAddr64(Addr64(bytes(8)))
    PH_TABLE:       vAddr64     = vAddr64(Addr64(ELF_PH_TABLE_64))
    SH_TABLE:       vAddr64     = StaticBytes(8).as_vaddr64()
    FLAGS:          StaticBytes = StaticBytes(4)
    H_SIZE:         StaticBytes = StaticBytes(2, ELF_HEADER_SIZE_64)
    PH_SIZE:        StaticBytes = StaticBytes(2, ELF_PH_TABLE_ENTRY_SIZE)
    PH_NUM:         StaticBytes = StaticBytes(2)
    SH_SIZE:        StaticBytes = StaticBytes(2, ELF_SH_TABLE_ENTRY_SIZE)
    SH_NUM:         StaticBytes = StaticBytes(2)
    SH_NAME:        StaticBytes = StaticBytes(2, ELF_SH_TABLE_NAMES)

    def __init__(self) -> None:
        pass
    
    def full_fill(self,
                  ENDIANESS: ENUM_ELF_ENDIAN,
                  ABI: ENUM_ELF_ABI,
                  ABI_VERSION: StaticBytes,
                  OBJECT_TYPE: ENUM_ELF_TYPE,
                  MACHINE: ENUM_ELF_ARCH,
                  ENTRY_POINT: Addr64,
                  PH_TABLE: Addr64,
                  SH_TABLE: Addr64,
                  FLAGS: StaticBytes,
                  PH_NUM: int,
                  SH_NUM: int,
                  SH_NAME: Addr64) -> None:
        pass

    def partial_fill(self,
                     ENDIANESS: ENUM_ELF_ENDIAN,
                     MACHINE: ENUM_ELF_ARCH,
                     ENTRY_POINT: vAddr64,
                     FLAGS: StaticBytes,
                     PH_NUM: int,
                     SH_NUM: int,
                     SH_NAME: StaticBytes) -> None:
        self.ENDIANESS = StaticBytes(1, ENDIANESS.value)
        if ENDIANESS == ENUM_ELF_ENDIAN.ELF_BIG_ENDIAN:
            self.ABI = StaticBytes(1, ENUM_ELF_ABI.ELF_ABI_DEFAULT.value)
            self.OBJECT_TYPE = StaticBytes(2,ENUM_ELF_TYPE.ELF_TYPE_EXEC.value)
            self.MACHINE = StaticBytes(2, MACHINE.value)
            self.FLAGS(FLAGS)
            self.PH_NUM = StaticBytes(2, PH_NUM.to_bytes(2, byteorder = 'big'))
            self.SH_NUM = StaticBytes(2, SH_NUM.to_bytes(2, byteorder = 'big'))
            self.SH_NAME(SH_NAME)
            self.ENTRY_POINT = ENTRY_POINT
        else:
            self.ABI = StaticBytes(1, ENUM_ELF_ABI.ELF_ABI_DEFAULT.value, True)
            self.OBJECT_TYPE = StaticBytes(2,ENUM_ELF_TYPE.ELF_TYPE_EXEC.value, True)
            self.MACHINE = StaticBytes(2, MACHINE.value, True)
            self.VERSION2.force_little()
            self.ENTRY_POINT = ENTRY_POINT
            self.ENTRY_POINT.addr.addr.force_little()
            self.PH_TABLE.addr.addr.force_little()
            self.SH_TABLE.addr.addr.force_little()
            self.FLAGS(FLAGS)
            self.FLAGS.force_little()
            self.H_SIZE.force_little()
            self.PH_SIZE.force_little()
            self.PH_NUM = StaticBytes(2, PH_NUM.to_bytes(2, byteorder = 'big'), True)
            self.SH_SIZE.force_little()
            self.SH_NUM = StaticBytes(2, SH_NUM.to_bytes(2, byteorder = 'big'), True)
            self.SH_NAME(SH_NAME)
            self.SH_NAME.force_little()
            #print(PH_NUM, SH_NUM, self.ENTRY_POINT.addr.addr.data, PH_NUM*int.from_bytes(ELF_PH_TABLE_ENTRY_SIZE, byteorder = 'little'),SH_NUM*int.from_bytes(ELF_SH_TABLE_ENTRY_SIZE, byteorder = 'little'),int.from_bytes(ELF_HEADER_SIZE_64, byteorder = 'little'),int("400000", 16))
            #print(self.ENTRY_POINT.addr.addr, self.PH_TABLE.addr.addr, self.SH_TABLE.addr.addr)

    def to_bytes(self) -> bytes:

        ret: bytearray = bytearray(64)
        ret[0:4] = self.MAGIC_BYTES.data
        ret[4:5] = self.BITS.data
        ret[5:6] = self.ENDIANESS.data
        ret[6:7] = self.VERSION.data
        ret[7:8] = self.ABI.data
        ret[8:9] = self.ABI_VERSION.data
        ret[9:16] = self.PADDING.data
        ret[16:18] = self.OBJECT_TYPE.data
        ret[18:20] = self.MACHINE.data
        ret[20:24] = self.VERSION2.data
        ret[24:32] = self.ENTRY_POINT.addr.addr.data
        ret[32:40] = self.PH_TABLE.addr.addr.data
        ret[40:48] = self.SH_TABLE.addr.addr.data
        ret[48:52] = self.FLAGS.data
        ret[52:54] = self.H_SIZE.data
        ret[54:56] = self.PH_SIZE.data
        ret[56:58] = self.PH_NUM.data
        ret[58:60] = self.SH_SIZE.data
        ret[60:62] = self.SH_NUM.data
        ret[62:64] = self.SH_NAME.data

        return bytes(ret)

    @classmethod
    def sizeof(cls) -> int:
        return 64


class PH_ENTRY:
    TYPE:           StaticBytes = StaticBytes(4)
    FLAGS:          StaticBytes = StaticBytes(4)
    OFFSET:         Addr64      = Addr64(bytes(8))
    VADDR:          vAddr64     = vAddr64(Addr64(bytes(8)))
    PADDR:          pAddr64     = pAddr64(Addr64(bytes(8)))
    FILESIZE:       StaticBytes = StaticBytes(8)
    MEMSIZE:        StaticBytes = StaticBytes(8)
    ALIGN:          StaticBytes = StaticBytes(8)

    def to_bytes(self) -> bytes:
        
        ret: bytearray = bytearray(PH_ENTRY.sizeof())

        ret[0:4] = self.TYPE.data
        ret[4:8] = self.FLAGS.data
        ret[8:16] = self.OFFSET.addr.data
        ret[16:24] = self.VADDR.addr.addr.data
        ret[24:32] = self.PADDR.addr.addr.data
        ret[32:40] = self.FILESIZE.data
        ret[40:48] = self.MEMSIZE.data
        ret[48:56] = self.ALIGN.data

        return bytes(ret)

    @classmethod
    def sizeof(cls) -> int:
        return 56

    def full_fill(self,
                  type: ELF_PH_TYPE,
                  flags: ELF_PH_FLAGS,
                  offset: StaticBytes,
                  vaddr: vAddr64,
                  paddr: pAddr64,
                  filesize: StaticBytes,
                  memsize: StaticBytes,
                  align: StaticBytes,
                  to_little: bool = False) -> None:
        if not to_little:
            self.TYPE        = StaticBytes(4,type.value)
            self.FLAGS       = StaticBytes(4,flags.to_bytes(4, 'big'))
            self.OFFSET      = offset.as_addr64()
            self.VADDR       = vaddr
            self.PADDR       = paddr
            self.FILESIZE    = filesize
            self.MEMSIZE     = memsize
            self.ALIGN       = align
        else:
            self.TYPE        = StaticBytes(4,type.value, True)
            self.FLAGS       = StaticBytes(4,flags.to_bytes(4, 'big'), True)
            self.OFFSET      = offset.as_addr64()
            self.OFFSET.addr.force_little()
            self.VADDR       = vaddr
            self.VADDR.addr.addr.force_little()
            self.PADDR       = paddr
            self.PADDR.addr.addr.force_little()
            self.FILESIZE    = filesize
            self.FILESIZE.force_little()
            self.MEMSIZE     = memsize
            self.MEMSIZE.force_little()
            self.ALIGN       = align
            self.ALIGN.force_little()
            print(self.ALIGN.data)

class SH_ENTRY:
    NAME:           StaticBytes = StaticBytes(4)
    TYPE:           StaticBytes = StaticBytes(4)
    FLAGS:          StaticBytes = StaticBytes(8)
    VADDR:          vAddr64     = vAddr64(Addr64(bytes(8)))
    OFFSET:         StaticBytes = StaticBytes(8)
    SIZE:           StaticBytes = StaticBytes(8)
    LINK:           StaticBytes = StaticBytes(4)
    INFO:           StaticBytes = StaticBytes(4)
    ADDRALIGN:      StaticBytes = StaticBytes(8)
    ENTRYSIZE:      StaticBytes = StaticBytes(8)

    def to_bytes(self) -> bytes:
        
        ret: bytearray = bytearray(60)

        ret[0:4] = self.NAME.data
        ret[4:8] = self.TYPE.data
        ret[8:16] = self.FLAGS.data
        ret[16:24] = self.VADDR.addr.addr.data
        ret[24:32] = self.OFFSET.data
        ret[32:40] = self.SIZE.data
        ret[40:44] = self.LINK.data
        ret[44:48] = self.INFO.data
        ret[48:56] = self.ADDRALIGN.data
        ret[56:64] = self.ENTRYSIZE.data

        return bytes(ret)

    @classmethod
    def sizeof(cls) -> int:
        return 64


def entry_point_addr() -> Addr64:
    return Addr64(bytes(8))

from math import ceil

@dataclass
class HeaderStructure:
    data: bytearray
    ph_offsets: list[int]
    sh_offsets: list[int]

    def __str__(self) -> str:
        data: str = "\n".join([ f'{" ".join([ f"{"\033[34;07m" if self.data[n] != 0 else ""}{hex(self.data[n]).replace('0x', '').capitalize():0>2}{"\033[m" if int(self.data[min(n+1,len(self.data)-1)]) == 0 or n == len(self.data)-1 else ""}" for n in range(x*8, min((x*8)+8,len(self.data))) ]):<24}| {hex(x+1).replace('0x','').capitalize():0>2}'  for x in range(ceil(len(self.data) / 8))])
        #data: str = "\n".join([ f"{str(bytes(self.data[x*8:min((x+1)*8, len(self.data))])).replace('\\x',' '):<28}| {hex(x+1)}" for x in range(ceil(len(self.data) / 8)) ])
        return data + f"\n\nph_offsets: {self.ph_offsets}\nsh_offsets: {self.sh_offsets}\n\nProposed entry address: {hex(0x400000 + len(self.data))}"

    def as_bytes(self) -> bytes:
        return bytes(self.data)

def gen_file_begin(ph_entries: int, sh_entries: int, align: int) -> HeaderStructure:

    ehsz: int = ELF64_HEADER.sizeof()
    phsz: int = PH_ENTRY.sizeof()
    shsz: int = SH_ENTRY.sizeof()

    ret: bytearray = bytearray(ehsz + phsz * (ph_entries+2) + shsz * sh_entries)

    ehobj: ELF64_HEADER = ELF64_HEADER()

    # Look good, should work

    phobjs: list[PH_ENTRY] = [PH_ENTRY(), PH_ENTRY()]

    phobjs[0].full_fill(ELF_PH_TYPE.PT_LOAD,
                        ELF_PH_FLAGS.EXEC | ELF_PH_FLAGS.READ,
                        StaticBytes(8,(len(ret)).to_bytes(8,'big')),
                        vAddr64(Addr64((int.from_bytes(ELF_DEFAULT_VIRTUAL_START) + len(ret)).to_bytes(8, 'big'))),
                        StaticBytes(8).as_paddr64(),
                        StaticBytes(8),
                        StaticBytes(8),
                        StaticBytes(8, int(align).to_bytes(8,'big')),
                        True)
    
    exec_size = 0

    phobjs[1].full_fill(ELF_PH_TYPE.PT_LOAD,
                        ELF_PH_FLAGS.WRIT | ELF_PH_FLAGS.READ,
                        StaticBytes(8,(len(ret)+exec_size).to_bytes(8,'big')),
                        vAddr64(Addr64((int.from_bytes(ELF_DEFAULT_VIRTUAL_START) + len(ret)+exec_size).to_bytes(8, 'big'))),
                        StaticBytes(8).as_paddr64(),
                        StaticBytes(8),
                        StaticBytes(8),
                        StaticBytes(8, int(align).to_bytes(8,'big')),
                        True)
    

    ehobj.partial_fill(ENUM_ELF_ENDIAN.ELF_LITTLE_ENDIAN,
                       ENUM_ELF_ARCH.ELF_ARCH_x86_64,
                       vAddr64(Addr64((int.from_bytes(ELF_DEFAULT_VIRTUAL_START) + len(ret)).to_bytes(8, 'big'))),
                       StaticBytes(4),
                       ph_entries+2,
                       sh_entries,
                       StaticBytes(2))

    phobjs += [PH_ENTRY() for x in range(ph_entries)]

    shobjs: list[SH_ENTRY] = []
    shobjs += [SH_ENTRY() for x in range(sh_entries)]

    shobjs_offset: int = ehsz+phsz*(ph_entries+2)

    ret[0:ehsz] = ehobj.to_bytes()
    for x, phobj in enumerate(phobjs):
        ret[ehsz + (x*phsz):ehsz + ((x+1)*phsz)] = phobj.to_bytes()
        print(phsz, len(phobj.to_bytes()))
        assert len(phobj.to_bytes()) == phsz, f"ASSERT: phsz {phsz} is different size than actual bytes output of phobj {len(phobj.to_bytes())}"
        assert phobj.to_bytes() == ret[ehsz + (x*phsz):ehsz + ((x+1)*phsz)], f"wrong write to ret"
        #print(phobj.to_bytes(), len(phobj.to_bytes()))
    print(ret[ehsz:ehsz+phsz])
    print(ret[ehsz+phsz:ehsz+phsz*2])
    for x, shobj in enumerate(shobjs):
        ret[shobjs_offset + (x*shsz):shobjs_offset + ((x+1)*shsz)] = shobj.to_bytes()

    return HeaderStructure(ret, [ehsz+(x*phsz) for x in range(ph_entries)], [shobjs_offset+(y*shsz) for y in range(sh_entries)])