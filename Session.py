class Session:
    def __init__(self, port, proto):
        self.port = port
        self.proto = proto

    def __hash__(self):
        return hash((self.port, self.proto))
    
    def __eq__(self, other):
        return (
            self.proto,
            self.port
        ) == (
            other.proto,
            other.port
        )