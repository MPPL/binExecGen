

class ExecFile:

    data: bytes
    exec_start: int = 0

    def __init__(self, *data: bytes) -> None:
        self.data = bytes(0)
        for x in data:
            self.data += x

    def set_exec_start(self, index: int):
        self.exec_start = index
    
    def to_bytes(self) -> bytes:
        return self.data
    
    def write_exec(self, data: bytes):
        if self.exec_start == 0:
            raise BufferError
        tmp: bytearray = bytearray(self.data)
        tmp[self.exec_start:len(data)] = data
        self.data = bytes(tmp)