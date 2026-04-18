import binary.formats.elf64 as m
import binary.arch.x86_64 as x86_64
from binary.arch.x86_64 import REG, linux_exit_list, linux_exit_raw, mov_r32_imm32, syscall
from binary.tools.string import nice_hex
from structs.files import ExecFile, DotData, DotCode, Header

def toh(n: int) -> str:
    return f"{hex(n).replace("0x",''):0>2}"

file = ExecFile(Header(b''), DotCode(m.ELF64.STANDARD_PAGE_SIZE*16, 0), DotData(m.ELF64.STANDARD_PAGE_SIZE*16, 0))

print(nice_hex(file.text.vaddr.addr.data))

file.append_data("Hello, World!\n".encode('ascii'))
file.append_exec(mov_r32_imm32(REG.RDI, 1))
file.append_exec(mov_r32_imm32(REG.RSI, file.text.vaddr.addr.as_int() + file.text.index[0]))
file.append_exec(mov_r32_imm32(REG.RDX, len("Hello, World!\n".encode('ascii'))))
file.append_exec(mov_r32_imm32(REG.RAX, 1))
file.append_exec(syscall())

for x in linux_exit_list():
    file.append_exec(x)

file = m.add_header_to_execfile(file)

a = file.as_bytes()

with open('mtest', 'wb') as f:
    f.write(a)

b: bytes
with open('main', 'rb') as f:
    b = f.read()



#print(nice_hex(x86_64.mov_r64_imm64(REG.RBX, 1)))           # mov rbx, 1
#print(nice_hex(x86_64.mov_r64_imm64(REG.RCX, 2)))           # mov rcx, 2
#print(nice_hex(x86_64.mov_r64_imm64(REG.RSI, 100)))         # mov rsi, 100
#print(nice_hex(x86_64.mov_r64_imm64(REG.RAX, 1000000000)))  # mov rax, 1000000000
#print(nice_hex(x86_64.mov_r64_imm64(REG.RDX, 123456)))      # mov rdx, 123456
#print(nice_hex(linux_exit_raw()))

print(nice_hex(a[0:0xB0]))

print(nice_hex((len(file.header) + len(file.code.as_bytes()) + m.ELF64.STANDARD_VIRTUAL_OFFSET).to_bytes(3)))