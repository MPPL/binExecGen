

ELF_IDENT: bytes = b'\x7F\x45\x4C\x46'

ELF_32: bytes = b'\x01'
ELF_64: bytes = b'\x02'

ELF_LITTLE_ENDIAN:  bytes = b'\x01'
ELF_BIG_ENDIAN:     bytes = b'\x02'

ELF_VERSION_BYTE:   bytes = b'\x01'

ELF_ABI_SYSTEMV:    bytes = b'\x00'
ELF_ABI_HP_UX:      bytes = b'\x01'
ELF_ABI_NETBSD:     bytes = b'\x02'
ELF_ABI_LINUX:      bytes = b'\x03'
ELF_ABI_GNUHURD:    bytes = b'\x04'
ELF_ABI_SOLARIS:    bytes = b'\x06'
ELF_ABI_AIX:        bytes = b'\x07'
ELF_ABI_IRIX:       bytes = b'\x08'
ELF_ABI_FREEBSD:    bytes = b'\x09'
ELF_ABI_TRU64:      bytes = b'\x0A'
ELF_ABI_NOVELL:     bytes = b'\x0B'
ELF_ABI_OPENBSD:    bytes = b'\x0C'
ELF_ABI_OPENVMS:    bytes = b'\x0D'
ELF_ABI_NONSTOP:    bytes = b'\x0E'
ELF_ABI_AROS:       bytes = b'\x0F'
ELF_ABI_FENIXOS:    bytes = b'\x10'
ELF_ABI_NUXI:       bytes = b'\x11'
ELF_ABI_OPENVOS:    bytes = b'\x12'

ELF_ABI_DEFAULT:    bytes = ELF_ABI_LINUX

ELF_ABI_VERSION_LINUX:  bytes = b'\x00'
ELF_ABI_PADDING:        bytes = b'\x00\x00\x00\x00\x00\x00\x00'

ELF_TYPE_NONE:      bytes = b'\x00\x00'
ELF_TYPE_REL:       bytes = b'\x01\x00'
ELF_TYPE_EXEC:      bytes = b'\x02\x00'
ELF_TYPE_DYN:       bytes = b'\x03\x00'
ELF_TYPE_CORE:      bytes = b'\x04\x00'
ELF_TYPE_LOOS:      bytes = b'\xFE\x00'
ELF_TYPE_HIOS:      bytes = b'\xFE\xFF'
ELF_TYPE_LOPROC:    bytes = b'\xFF\x00'
ELF_TYPE_HIPROC:    bytes = b'\xFF\xFF'


#UNFINISHED
ELF_ARCH_NONE:          bytes = b'\x00\x00'
ELF_ARCH_ATnT_WE_32100: bytes = b'\x01\x00'
ELF_ARCH_SPARC:         bytes = b'\x02\x00'
ELF_ARCH_x86:           bytes = b'\x03\x00'
ELF_ARCH_M68K:          bytes = b'\x04\x00'
ELF_ARCH_M88K:          bytes = b'\x05\x00'
ELF_ARCH_INTEL_MCU:     bytes = b'\x06\x00'
ELF_ARCH_INTEL_80860:   bytes = b'\x07\x00'
ELF_ARCH_MIPS:          bytes = b'\x08\x00'
ELF_ARCH_IBM_370:       bytes = b'\x09\x00'
ELF_ARCH_MIPS_RE3K_LE:  bytes = b'\x0A\x00'
# ...
ELF_ARCH_ARM:           bytes = b'\x28\x00'
ELF_ARCH_x86_64:        bytes = b'\x3E\x00'
ELF_ARCH_ARM64:         bytes = b'\xB7\x00'
ELF_ARCH_RISC_V:        bytes = b'\xF3\x00'

ELF_ARCH_DEFAULT:       bytes = ELF_ARCH_x86_64

ELF_2ND_VERSION_BYTE:   bytes = b'\x00\x00\x00\x01'

ELF_ENTRY_POINT:        bytes = b''

ELF_PH_TABLE_32:        bytes = b'\x00\x00\x00\x34'

ELF_SH_TABLE:           bytes = b'\x00\x00\x00\x00'

ELF_CPU_FLAGS:          bytes = b'\x00\x00'

ELF_HEADER_SIZE_32:     bytes = b'\x00\x34'

ELF_PH_TABLE_SIZE_32:   bytes = b'\x00\x00\x00\x34'
ELF_PH_TABLE_SIZE_64:   bytes = b'\x00\x00\x00\x40'

ELF_PH_TABLE_ENTRIES:   bytes = b'\x00\x01'

ELF_SH_TABLE_ENTRY_SIZE:bytes = b'\x00\x00'
ELF_SH_TABLE_ENTRIES:   bytes = b'\x00\x00'
ELF_SH_TABLE_NAMES:     bytes = b'\x00\x00'