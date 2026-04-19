def nice_hex(data: bytes, break_line_at: int = 0) -> str:
    if break_line_at < 1:
        return f"{" ".join([ f"{hex(x).replace('0x', ''):0>2}" for x in data]) }"
    return f" {" ".join([ f"{hex(x).replace('0x', ''):0>2}{'\n' if (n+1) % break_line_at == 0 else ''}" for n, x in enumerate(data)]) }"