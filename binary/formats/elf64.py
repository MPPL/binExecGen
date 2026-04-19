from structs.binary import Addr64, StaticBytes
from dataclasses import dataclass
from typing import Literal
from enum import Enum, IntFlag
from binary.tools.string import nice_hex
from math import ceil
from structs.files import ExecFile, Header, DotCode, DotData
from binary.tools.convert import extend, fit_in_align
from mmap import PAGESIZE

class ELF64:

    IDENT: bytes = b'\x7F\x45\x4C\x46'
    BYTES = b'\x02'
    class ENUM_ENDIAN(Enum):
        LITTLE_ENDIAN = b'\x01'
        BIG_ENDIAN    = b'\x02'

    VERSION_BYTE:   bytes = b'\x01'

    class ENUM_ABI(Enum):
        ABI_SYSTEMV      = b'\x00'
        ABI_HP_UX        = b'\x01'
        ABI_NETBSD       = b'\x02'
        ABI_LINUX        = b'\x03'
        ABI_GNUHURD      = b'\x04'
        ABI_SOLARIS      = b'\x06'
        ABI_AIX          = b'\x07'
        ABI_IRIX         = b'\x08'
        ABI_FREEBSD      = b'\x09'
        ABI_TRU64        = b'\x0A'
        ABI_NOVELL       = b'\x0B'
        ABI_OPENBSD      = b'\x0C'
        ABI_OPENVMS      = b'\x0D'
        ABI_NONSTOP      = b'\x0E'
        ABI_AROS         = b'\x0F'
        ABI_FENIXOS      = b'\x10'
        ABI_NUXI         = b'\x11'
        ABI_OPENVOS      = b'\x12'
        ABI_DEFAULT      = ABI_SYSTEMV

    ABI_VERSION_LINUX:  bytes = b'\x00'
    ABI_PADDING:        bytes = b'\x00\x00\x00\x00\x00\x00\x00'

    class ENUM_TYPE(Enum):
        TYPE_NONE        = b'\x00\x00'
        TYPE_REL         = b'\x00\x01'
        TYPE_EXEC        = b'\x00\x02'
        TYPE_DYN         = b'\x00\x03'
        TYPE_CORE        = b'\x00\x04'
        TYPE_LOOS        = b'\xFE\x00'
        TYPE_HIOS        = b'\xFE\xFF'
        TYPE_LOPROC      = b'\xFF\x00'
        TYPE_HIPROC      = b'\xFF\xFF'

    #UNFINISHED
    class ENUM_ARCH(Enum):
        ARCH_NONE           = b'\x00\x00'
        ARCH_ATnT_WE_32100  = b'\x00\x01'
        ARCH_SPARC          = b'\x00\x02'
        ARCH_x86            = b'\x00\x03'
        ARCH_M68K           = b'\x00\x04'
        ARCH_M88K           = b'\x00\x05'
        ARCH_INTEL_MCU      = b'\x00\x06'
        ARCH_INTEL_80860    = b'\x00\x07'
        ARCH_MIPS           = b'\x00\x08'
        ARCH_IBM_370        = b'\x00\x09'
        ARCH_MIPS_RE3K_LE   = b'\x00\x0A'
        # ...
        ARCH_ARM            = b'\x00\x28'
        ARCH_x86_64         = b'\x00\x3E'
        ARCH_ARM64          = b'\x00\xB7'
        ARCH_RISC_V         = b'\x00\xF3'

        ARCH_DEFAULT        = ARCH_x86_64

    VERSION_BYTE_2:   bytes = b'\x00\x00\x00\x01'

    #ENTRY_POINT:        bytes = bytes(8)
    #PH_TABLE_64:        bytes = b'\x00\x00\x00\x00\x00\x00\x00\x40'
    #SH_TABLE_64:        bytes = b'\x00\x00\x00\x00\x00\x00\x00\x40'
    #CPU_FLAGS:          bytes = b'\x00\x00'

    HEADER_SIZE_64:     bytes = b'\x00\x40'
    PH_TABLE_SIZE_64:   bytes = b'\x00\x00\x00\x40'
    PH_TABLE_ENTRY_SIZE:bytes = b'\x00\x38'
    #PH_TABLE_ENTRIES:   bytes = b'\x00\x01'

    SH_TABLE_ENTRY_SIZE:bytes = b'\x00\x40'
    #SH_TABLE_ENTRIES:   bytes = b'\x00\x00'
    #SH_TABLE_NAMES:     bytes = b'\x00\x00'

    STANDARD_PAGE_SIZE:       int = 4096
    STANDARD_VIRTUAL_OFFSET:  int = 4194304

    class PH_TYPE(Enum):
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

    class PH_FLAGS(IntFlag):
        EXEC = 1
        WRIT = 2
        READ = 4


class ELF64_HEADER:
    MAGIC_BYTES:    StaticBytes = StaticBytes(4, ELF64.IDENT)
    BITS:           StaticBytes = StaticBytes(1, ELF64.BYTES)
    ENDIANESS:      StaticBytes = StaticBytes(1, ELF64.ENUM_ENDIAN.BIG_ENDIAN.value)
    VERSION:        StaticBytes = StaticBytes(1, ELF64.VERSION_BYTE)
    ABI:            StaticBytes = StaticBytes(1)
    ABI_VERSION:    StaticBytes = StaticBytes(1)
    PADDING:        StaticBytes = StaticBytes(7)
    OBJECT_TYPE:    StaticBytes = StaticBytes(2)
    MACHINE:        StaticBytes = StaticBytes(2)
    VERSION2:       StaticBytes = StaticBytes(4, ELF64.VERSION_BYTE_2)
    ENTRY_POINT:    Addr64      = Addr64(bytes(8))
    PH_TABLE:       StaticBytes = StaticBytes(8, extend(ELF64.HEADER_SIZE_64, 6))
    SH_TABLE:       StaticBytes = StaticBytes(8)
    FLAGS:          StaticBytes = StaticBytes(4)
    H_SIZE:         StaticBytes = StaticBytes(2, ELF64.HEADER_SIZE_64)
    PH_SIZE:        StaticBytes = StaticBytes(2, ELF64.PH_TABLE_ENTRY_SIZE)
    PH_NUM:         StaticBytes = StaticBytes(2)
    SH_SIZE:        StaticBytes = StaticBytes(2, ELF64.SH_TABLE_ENTRY_SIZE)
    SH_NUM:         StaticBytes = StaticBytes(2)
    SH_NAME:        StaticBytes = StaticBytes(2)

    def __init__(self) -> None:
        pass
    
    def full_fill(self,
                ENDIANESS: ELF64.ENUM_ENDIAN,
                ABI: ELF64.ENUM_ABI,
                ABI_VERSION: StaticBytes,
                OBJECT_TYPE: ELF64.ENUM_TYPE,
                MACHINE: ELF64.ENUM_ARCH,
                ENTRY_POINT: Addr64,
                PH_TABLE: Addr64,
                SH_TABLE: Addr64,
                FLAGS: StaticBytes,
                PH_NUM: int,
                SH_NUM: int,
                SH_NAME: Addr64) -> None:
        pass

    def partial_fill(self,
                    ENDIANESS: ELF64.ENUM_ENDIAN,
                    MACHINE: ELF64.ENUM_ARCH,
                    ENTRY_POINT: Addr64,
                    FLAGS: StaticBytes,
                    PH_NUM: int,
                    SH_NUM: int,
                    SH_NAME: StaticBytes) -> None:
        self.ENDIANESS = StaticBytes(1, ENDIANESS.value)
        if ENDIANESS == ELF64.ENUM_ENDIAN.BIG_ENDIAN:
            self.ABI = StaticBytes(1, ELF64.ENUM_ABI.ABI_DEFAULT.value)
            self.OBJECT_TYPE = StaticBytes(2,ELF64.ENUM_TYPE.TYPE_EXEC.value)
            self.MACHINE = StaticBytes(2, MACHINE.value)
            self.ENTRY_POINT = ENTRY_POINT
            self.SH_TABLE = StaticBytes(8,(int.from_bytes(ELF64.HEADER_SIZE_64) + int.from_bytes(ELF64.PH_TABLE_ENTRY_SIZE) * PH_NUM).to_bytes(8, 'big')) if SH_NUM > 0 else StaticBytes(8)
            self.FLAGS(FLAGS)
            self.PH_NUM = StaticBytes(2, PH_NUM.to_bytes(2, byteorder = 'big'))
            self.SH_NUM = StaticBytes(2, SH_NUM.to_bytes(2, byteorder = 'big'))
            self.SH_NAME(SH_NAME)
        else:
            self.ABI = StaticBytes(1, ELF64.ENUM_ABI.ABI_DEFAULT.value, True)
            self.OBJECT_TYPE = StaticBytes(2,ELF64.ENUM_TYPE.TYPE_EXEC.value, True)
            self.MACHINE = StaticBytes(2, MACHINE.value, True)
            self.VERSION2.convert_to_little()
            self.ENTRY_POINT = ENTRY_POINT
            self.ENTRY_POINT.addr.convert_to_little()
            self.PH_TABLE = StaticBytes(8, extend(ELF64.HEADER_SIZE_64,6), True)
            self.SH_TABLE = StaticBytes(8,(int.from_bytes(ELF64.HEADER_SIZE_64) + int.from_bytes(ELF64.PH_TABLE_ENTRY_SIZE) * PH_NUM).to_bytes(8, 'big'), True) if SH_NUM > 0 else StaticBytes(8, to_little=True)
            self.FLAGS(FLAGS)
            self.FLAGS.convert_to_little()
            self.H_SIZE.convert_to_little()
            self.PH_SIZE.convert_to_little()
            self.PH_NUM = StaticBytes(2, PH_NUM.to_bytes(2, byteorder = 'big'), True)
            self.SH_SIZE.convert_to_little()
            self.SH_NUM = StaticBytes(2, SH_NUM.to_bytes(2, byteorder = 'big'), True)
            self.SH_NAME(SH_NAME)
            self.SH_NAME.convert_to_little()
            #print(PH_NUM, SH_NUM, self.ENTRY_POINT.addr.addr.data, PH_NUM*int.from_bytes(PH_TABLE_ENTRY_SIZE, byteorder = 'little'),SH_NUM*int.from_bytes(SH_TABLE_ENTRY_SIZE, byteorder = 'little'),int.from_bytes(HEADER_SIZE_64, byteorder = 'little'),int("400000", 16))
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
        ret[24:32] = self.ENTRY_POINT.addr.data
        ret[32:40] = self.PH_TABLE.data
        ret[40:48] = self.SH_TABLE.data
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
    VADDR:          Addr64      = Addr64(bytes(8))
    PADDR:          Addr64      = Addr64(bytes(8))
    FILESIZE:       StaticBytes = StaticBytes(8)
    MEMSIZE:        StaticBytes = StaticBytes(8)
    ALIGN:          StaticBytes = StaticBytes(8)

    def to_bytes(self) -> bytes:
        
        ret: bytearray = bytearray(PH_ENTRY.sizeof())

        ret[0:4] = self.TYPE.data
        ret[4:8] = self.FLAGS.data
        ret[8:16] = self.OFFSET.addr.data
        ret[16:24] = self.VADDR.addr.data
        ret[24:32] = self.PADDR.addr.data
        ret[32:40] = self.FILESIZE.data
        ret[40:48] = self.MEMSIZE.data
        ret[48:56] = self.ALIGN.data

        return bytes(ret)

    @classmethod
    def sizeof(cls) -> int:
        return 56

    def full_fill(self,
                type:         ELF64.PH_TYPE,
                flags:        ELF64.PH_FLAGS,
                offset:       StaticBytes,
                vaddr:        Addr64,
                paddr:        Addr64,
                filesize:     StaticBytes,
                memsize:      StaticBytes,
                align:        StaticBytes,
                to_little:    bool = False) -> None:
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
            self.OFFSET.addr.convert_to_little()
            self.VADDR       = vaddr
            self.VADDR.addr.convert_to_little()
            self.PADDR       = paddr
            self.PADDR.addr.convert_to_little()
            self.FILESIZE    = filesize
            self.FILESIZE.convert_to_little()
            self.MEMSIZE     = memsize
            self.MEMSIZE.convert_to_little()
            self.ALIGN       = align
            self.ALIGN.convert_to_little()

class SH_ENTRY:
    NAME:           StaticBytes = StaticBytes(4)
    TYPE:           StaticBytes = StaticBytes(4)
    FLAGS:          StaticBytes = StaticBytes(8)
    VADDR:          Addr64      = Addr64(bytes(8))
    OFFSET:         StaticBytes = StaticBytes(8)
    SIZE:           StaticBytes = StaticBytes(8)
    LINK:           StaticBytes = StaticBytes(4)
    INFO:           StaticBytes = StaticBytes(4)
    ADDRALIGN:      StaticBytes = StaticBytes(8)
    ENTRYSIZE:      StaticBytes = StaticBytes(8)

    def to_bytes(self) -> bytes:
        
        ret: bytearray = bytearray(60)

        ret[0:4]    = self.NAME.data
        ret[4:8]    = self.TYPE.data
        ret[8:16]   = self.FLAGS.data
        ret[16:24]  = self.VADDR.addr.data
        ret[24:32]  = self.OFFSET.data
        ret[32:40]  = self.SIZE.data
        ret[40:44]  = self.LINK.data
        ret[44:48]  = self.INFO.data
        ret[48:56]  = self.ADDRALIGN.data
        ret[56:64]  = self.ENTRYSIZE.data

        return bytes(ret)

    @classmethod
    def sizeof(cls) -> int:
        return 64

from math import ceil

@dataclass
class HeaderStructure:
    data: bytearray
    ph_offsets: list[int]
    ph_vaddr: list[Addr64]
    sh_offsets: list[int]
    align: int

    def __str__(self) -> str:
        data: str = "\n".join([ f'{" ".join([ f"{"\033[34;07m" if self.data[n] != 0 else ""}{hex(self.data[n]).replace('0x', '').capitalize():0>2}{"\033[m" if int(self.data[min(n+1,len(self.data)-1)]) == 0 or n == len(self.data)-1 else ""}" for n in range(x*8, min((x*8)+8,len(self.data))) ]):<24}| {hex(x+1).replace('0x','').capitalize():0>2}'  for x in range(ceil(len(self.data) / 8))])
        #data: str = "\n".join([ f"{str(bytes(self.data[x*8:min((x+1)*8, len(self.data))])).replace('\\x',' '):<28}| {hex(x+1)}" for x in range(ceil(len(self.data) / 8)) ])
        return data + f"\n\nph_offsets: {self.ph_offsets}\nsh_offsets: {self.sh_offsets}\n\nProposed entry address: {hex(0x400000 + len(self.data))}"

    def as_bytes(self) -> bytes:
        tmp: bytearray = bytearray(fit_in_align(len(self.data), self.align))
        tmp[:len(self.data)] = self.data
        return bytes(tmp)
    
    def __len__(self) -> int:
        return fit_in_align(len(self.data), self.align)

def get_header_size(ph_entries: int, sh_entries: int) -> int:
    return (ELF64_HEADER.sizeof() + PH_ENTRY.sizeof() * ph_entries + SH_ENTRY.sizeof() * sh_entries)

def get_data_offset(header_size: int, header_align: int = ELF64.STANDARD_PAGE_SIZE) -> int:
    return ceil(header_size / header_align) * header_align

def gen_ph_entry(type: ELF64.PH_TYPE,
                flags: ELF64.PH_FLAGS,
                offset: int,
                virtual_offset: int,
                physical_offset: int,
                filesize: int,
                memsize: int,
                alignment: int,
                is_little: bool = False) -> PH_ENTRY:
    ret: PH_ENTRY = PH_ENTRY()
    ret.full_fill(type,
                flags,
                StaticBytes(8,offset.to_bytes(8)),
                Addr64(StaticBytes(8,virtual_offset.to_bytes(8))),
                Addr64(StaticBytes(8,physical_offset.to_bytes(8))),
                StaticBytes(8,filesize.to_bytes(8)),
                StaticBytes(8,memsize.to_bytes(8)),
                StaticBytes(8,alignment.to_bytes(8)),
                is_little)
    return ret

def gen_default_header(exec_size: int, rw_data_size: int) -> HeaderStructure:

    hdsz: int = ELF64_HEADER.sizeof()
    phsz: int = PH_ENTRY.sizeof()
    shsz: int = SH_ENTRY.sizeof()

    ret_data: bytearray = bytearray(get_header_size(2, 0))

    ph_exec: PH_ENTRY = gen_ph_entry(
        ELF64.PH_TYPE.PT_LOAD,
        ELF64.PH_FLAGS.READ | ELF64.PH_FLAGS.EXEC,
        #get_data_offset(len(ret_data)),
        0,
        ELF64.STANDARD_VIRTUAL_OFFSET,
        0,
        exec_size + ELF64.STANDARD_PAGE_SIZE,
        fit_in_align(exec_size + ELF64.STANDARD_PAGE_SIZE, ELF64.STANDARD_PAGE_SIZE),
        ELF64.STANDARD_PAGE_SIZE,
        True)

    ph_data: PH_ENTRY = gen_ph_entry(
        ELF64.PH_TYPE.PT_LOAD,
        ELF64.PH_FLAGS.READ | ELF64.PH_FLAGS.WRIT,
        get_data_offset(len(ret_data)) + fit_in_align(exec_size, ELF64.STANDARD_PAGE_SIZE),
        ELF64.STANDARD_VIRTUAL_OFFSET + fit_in_align(exec_size + ELF64.STANDARD_PAGE_SIZE, ELF64.STANDARD_PAGE_SIZE),
        0,
        rw_data_size,
        fit_in_align(rw_data_size, ELF64.STANDARD_PAGE_SIZE),
        ELF64.STANDARD_PAGE_SIZE,
        True)

    ident_header: ELF64_HEADER = ELF64_HEADER()
    ident_header.partial_fill(ELF64.ENUM_ENDIAN.LITTLE_ENDIAN,
                            ELF64.ENUM_ARCH.ARCH_DEFAULT,
                            Addr64(StaticBytes(8,(ELF64.STANDARD_VIRTUAL_OFFSET + ELF64.STANDARD_PAGE_SIZE).to_bytes(8))),
                            StaticBytes(4),
                            2,
                            0,
                            StaticBytes(2))
    
    ret_data[0:hdsz] = ident_header.to_bytes()
    ret_data[hdsz:hdsz + phsz] = ph_exec.to_bytes()
    ret_data[hdsz + phsz:hdsz + phsz*2] = ph_data.to_bytes()

    #print(nice_hex(ph_data.VADDR.addr.data))

    return HeaderStructure(ret_data, [get_data_offset(len(ret_data)),get_data_offset(len(ret_data))], [ph_exec.VADDR, ph_data.VADDR] ,[], ELF64.STANDARD_PAGE_SIZE)

def gen_test_file() -> ExecFile:

    exec_bytes: int = fit_in_align(12345,ELF64.STANDARD_PAGE_SIZE)
    rw_bytes: int = fit_in_align(10000,ELF64.STANDARD_PAGE_SIZE)

    header: HeaderStructure = gen_default_header(exec_bytes, rw_bytes)

    hdend: int = ELF64.STANDARD_PAGE_SIZE
    exend: int = hdend + exec_bytes
    align: int = ELF64.STANDARD_PAGE_SIZE

    return ExecFile(Header(header.as_bytes() + bytes(ELF64.STANDARD_PAGE_SIZE - len(header.as_bytes()))), DotCode(exec_bytes, align, hdend, header.ph_vaddr[0]), DotData(rw_bytes, align, exend, header.ph_vaddr[1]))

def add_header_to_execfile(file: ExecFile) -> ExecFile:

    header: HeaderStructure = gen_default_header(file.get_symbol_len(),len(file.text.as_bytes()))

    file.header.data = header.as_bytes()

    file.code.set_offset(header.ph_offsets[0])
    file.code.set_vaddr(header.ph_vaddr[0])
    file.code.set_align(ELF64.STANDARD_PAGE_SIZE)
    file.text.set_offset(header.ph_offsets[1])
    file.text.set_vaddr(header.ph_vaddr[1])
    file.text.set_align(ELF64.STANDARD_PAGE_SIZE)

    return file