import struct
from dataclasses import dataclass
from typing import ClassVar

import python_dns_client.utils as utils
from python_dns_client.constants import SHORT_INT_RANGE, TWO_BYTE_STRUCT


@dataclass(frozen=True)
class DNSHeaderFlags:
    qr: bool
    aa: bool
    tc: bool
    rd: bool
    ra: bool

    QR_MASK: ClassVar = 0x8000
    AA_MASK: ClassVar = 0x0400
    TC_MASK: ClassVar = 0x0200
    RD_MASK: ClassVar = 0x0100
    RA_MASK: ClassVar = 0x0080

    @classmethod
    def default(cls):
        return cls(False, False, False, False, False)

    @classmethod
    def query_flags(cls):
        return cls(False, False, False, True, False)

    @classmethod
    def parse(cls, container: int):
        assert container in SHORT_INT_RANGE

        qr = utils.is_set(container, DNSHeaderFlags.QR_MASK)
        aa = utils.is_set(container, DNSHeaderFlags.AA_MASK)
        tc = utils.is_set(container, DNSHeaderFlags.TC_MASK)
        rd = utils.is_set(container, DNSHeaderFlags.RD_MASK)
        ra = utils.is_set(container, DNSHeaderFlags.RA_MASK)

        return cls(qr, aa, tc, rd, ra)

    def to_int(self) -> int:
        b = 0

        flags = self.qr, self.aa, self.tc, self.rd, self.ra
        masks = (
            DNSHeaderFlags.QR_MASK,
            DNSHeaderFlags.AA_MASK,
            DNSHeaderFlags.TC_MASK,
            DNSHeaderFlags.RD_MASK,
            DNSHeaderFlags.RA_MASK,
        )

        for flag, mask in zip(flags, masks):
            if flag:
                b |= mask

        return b

    def to_bytes(self) -> bytes:
        return TWO_BYTE_STRUCT.pack(self.to_int())


@dataclass(frozen=True)
class DNSHeader:
    _id: int  # 2 bytes

    # qr: bool  # 1 bit
    # aa: bool  # 1 bit
    # tc: bool  # 1 bit
    # rd: bool  # 1 bit
    # ra: bool  # 1 bit
    flags: DNSHeaderFlags

    z: int  # 3 bits
    rcode: int  # 4 bits

    qd_count: int  # 2 bytes - short
    an_count: int  # 2 bytes
    ns_count: int  # 2 bytes
    ar_count: int  # 2 bytes

    # opcode: int = 0

    STRUCT: ClassVar = struct.Struct("! 6H")
    RCODE_MASK: ClassVar = 0x0F
    Z_MASK: ClassVar = 0x70

    Z_DEFAULT: ClassVar = 2

    @classmethod
    def create(cls, flags: DNSHeaderFlags, questions: int, answers: int):
        id_ = utils.generate_new_short_id()

        return cls(id_, flags, DNSHeader.Z_DEFAULT, 0, questions, answers, 0, 0)

    @classmethod
    def query_header(cls, questions: int):
        flags = DNSHeaderFlags.query_flags()

        return cls.create(flags, questions, 0)

    @classmethod
    def parse(cls, b: bytes):
        assert len(b) == 12

        (
            _id,
            flags_container,
            qd_count,
            an_count,
            ns_count,
            ar_count,
        ) = DNSHeader.STRUCT.unpack(b)

        rcode = flags_container & DNSHeader.RCODE_MASK
        z = (flags_container & DNSHeader.Z_MASK) >> 4

        flags = DNSHeaderFlags.parse(flags_container)

        return cls(_id, flags, z, rcode, qd_count, an_count, ns_count, ar_count)

    def to_bytes(self) -> bytes:
        _id = self._id
        flags_container = self.flags.to_int()

        # Add Z code

        # Discard the rcode bits as they are zero anyways at this point
        flags_container >>= 4
        flags_container += self.z
        flags_container <<= 4

        flags_container += self.rcode  # last 4 bits, so no shifts needed

        qd_count, an_count, ns_count, ar_count = (
            self.qd_count,
            self.an_count,
            self.ns_count,
            self.ar_count,
        )

        return DNSHeader.STRUCT.pack(
            _id, flags_container, qd_count, an_count, ns_count, ar_count
        )
