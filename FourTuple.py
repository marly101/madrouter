class FourTuple:
    def __init__(self, internal_IP, internal_port, external_ip, external_port, proto):
        self.internal_ip = internal_IP
        self.internal_port = internal_port
        self.external_ip = external_ip
        self.external_port = external_port
        self.proto = proto

    def __eq__(self, other):
        return (
            self.internal_ip,
            self.internal_port,
            self.external_ip,
            self.external_port,
            self.proto
        ) == (
            other.internal_ip,
            other.internal_port,
            other.external_ip,
            other.external_port,
            other.proto
        )    
    
    def __hash__(self):
        return hash ((
            self.internal_ip,
            self.internal_port,
            self.external_ip,
            self.external_port,
            self.proto
        ))