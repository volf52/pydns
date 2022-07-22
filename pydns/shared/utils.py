# -*- coding: utf-8 -*-
import random
import time

from pydns.shared.constants import MAX_SHORT_INT

random.seed(time.time())


def generate_new_short_id():
    return random.randint(0, MAX_SHORT_INT)


def get_bit_string(n: int, length=8):
    return bin(n)[2:].zfill(length)


def get_hex_string(n: int, byte_length=1):
    return n.to_bytes(byte_length, byteorder="big")


def is_set(n: int, mask: int) -> bool:
    return (n & mask) != 0
