import typing


class Packable(typing.Protocol):
    def to_bytes(self) -> bytes:
        ...
