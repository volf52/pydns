# -*- coding: utf-8 -*-
import struct

MAX_SHORT_INT = 2**16 - 1
SHORT_INT_RANGE = range(MAX_SHORT_INT + 1)

NULL_BYTE = b"\x00"

ONE_BYTE_STRUCT = struct.Struct("! B")
TWO_BYTE_STRUCT = struct.Struct("! H")
FOUR_BYTE_STRUCT = struct.Struct("! I")

ONE_AS_BYTE = b"x01"  # struct.pack("! H", 1)
ONE_AS_SHORT = b"\x00\x01"  # struct.pack("! H", 1)
