

class ExecFile:

    data: bytes

    def __init__(self, *data: bytes) -> None:
        self.data = bytes(0)
        for x in data:
            self.data += x
    
    def to_bytes(self) -> bytes:
        return self.data