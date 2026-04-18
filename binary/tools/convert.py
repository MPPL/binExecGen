from math import ceil

def BTLEndian(data: bytes) -> bytes:
    return bytes(reversed(data.lstrip(b'\x00'))) + bytes(len(data) - len(data.lstrip(b'\x00')))

def LTBEndian(data: bytes) -> bytes:
    return bytes(len(data) - len(data.rstrip(b'\x00'))) + bytes(reversed(data.rstrip(b'\x00')))

def extend(data: bytes, by_lenght: int, is_little: bool = False) -> bytes:

    if by_lenght <= 0:
        return data     # MAY CAUSE BUGS

    if is_little:
        return data + bytes(by_lenght)
    else:
        return bytes(by_lenght) + data

def shorten(data: bytes, by_lenght: int, is_little: bool = False) -> bytes:

    if by_lenght <= 0:
        return data     # MAY CAUSE BUGS

    if by_lenght > len(data):
        raise ValueError
    if is_little:
        return data[:-by_lenght]
    else:
        return data[by_lenght:]

def fit_in_align(val: int, align: int) -> int:
    if align <= 1:
        return val
    return ceil(val / align) * align