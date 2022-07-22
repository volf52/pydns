# -*- coding: utf-8 -*-
import socket

from pydns.dns.packet import DNSPacket
from pydns.dns.query import DNSQuery

DNS_SERVER = "8.8.8.8"
DNS_PORT = 53

# googlev6 = 2a00:1450:4019:80a::200e

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    print("Connecting...")
    sock.connect((DNS_SERVER, DNS_PORT))
    print("Connected!")

    query = DNSQuery.cname_query("api.carbonteq-livestream.ml")
    query_bytes = query.to_bytes()

    sock.send(query_bytes)

    resp = sock.recv(1024)

    # with open("test_data/test_resp", "wb") as f:
    #     f.write(resp)

    resp_packet = DNSPacket.parse(resp)
    assert resp_packet.header.an_count > 0

    print("---------- Answers --------------")
    for ans in resp_packet.answers:
        print(ans)
finally:
    sock.close()
    print("Done")
