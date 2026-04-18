def nice_hex(data: bytes) -> str:
    return f"{" ".join([ f"{hex(x).replace('0x', ''):0>2}" for x in data]) }"