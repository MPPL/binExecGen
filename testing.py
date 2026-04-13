import binary.formats.elf64 as m

def toh(n: int) -> str:
    return f"{hex(n).replace("0x",''):0>2}"

a = m.gen_file_begin(0,0,16).as_bytes()

with open('mtest', 'wb') as f:
    f.write(a)

b: bytes
with open('main', 'rb') as f:
    b = f.read()

for n, x in enumerate(a):
    if n % 16 == 0:
        print("")
    #if x != b[n]:
        #print(f"!!! -   {toh(x)} | {toh(b[n])}   >|< {toh(n)}")
    #else:
        #print(f"+++ -   {toh(x)} | {toh(b[n])}   >|< {toh(n)}")