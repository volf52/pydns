# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DNSBuffer:
    __b: bytes

    __len: int
    __pos: int = 0

    @classmethod
    def create(cls, b: bytes) -> DNSBuffer:
        return DNSBuffer(b, len(b))

    def at(self, idx: int) -> int:
        return self.__b[idx]

    def get_slice(self, start: int, stop: int = -1) -> bytes:
        if stop == -1:
            stop = self.__len

        return self.__b[start:stop]

    def get(self, n_bytes: int) -> bytes:
        # todo: add error handling
        b = self.__b[self.pos : self.pos + n_bytes]
        self.__pos += n_bytes

        return b

    def pop(self) -> int:
        b = self.__b[self.__pos]
        self.__pos += 1

        return b

    def incr(self) -> None:
        self.__pos += 1

    @property
    def peek(self) -> int:
        return self.__b[self.__pos]

    @property
    def b(self) -> bytes:
        return self.__b

    @property
    def left(self) -> int:
        return self.__len - self.__pos

    @property
    def pos(self) -> int:
        return self.__pos

    # def __getitem__(self, slice_idx):
    #     if isinstance(slice_idx, slice):
    #         return self.__b[slice_idx.start : slice_idx.stop : slice_idx.step]

    #     return self.__b[slice_idx]

    def __len__(self) -> int:
        return self.__len
