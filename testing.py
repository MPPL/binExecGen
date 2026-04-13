import binary.formats.elf64 as m
import binary.arch.x86_64 as x86_64
from binary.arch.x86_64 import REG

def toh(n: int) -> str:
    return f"{hex(n).replace("0x",''):0>2}"

a = m.gen_test_file().to_bytes()

with open('mtest', 'wb') as f:
    f.write(a)

b: bytes
with open('main', 'rb') as f:
    b = f.read()

def nice_hex(data: bytes) -> str:
    return f"{" ".join([ f"{hex(x).replace('0x', ''):0>2}" for x in data]) }"

print(nice_hex(x86_64.mov_r64_imm64(REG.RBX, 1)))           # mov rbx, 1
print(nice_hex(x86_64.mov_r64_imm64(REG.RCX, 2)))           # mov rcx, 2
print(nice_hex(x86_64.mov_r64_imm64(REG.RSI, 100)))         # mov rsi, 100
print(nice_hex(x86_64.mov_r64_imm64(REG.RAX, 10000000000))) # mov rax, 10000000000
print(nice_hex(x86_64.mov_r64_imm64(REG.RDX, 123456)))      # mov rdx, 123456