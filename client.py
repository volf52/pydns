# -*- coding: utf-8 -*-
import socket

from python_dns_client.dns.packet import DNSPacket
from python_dns_client.dns.query import DNSQuery

DNS_SERVER = "8.8.8.8"
DNS_PORT = 53

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    print("Connecting...")
    sock.connect((DNS_SERVER, DNS_PORT))
    print("Connected!")

    query = DNSQuery.ip_query("api.carbonteq-livestream.ml")
    query_bytes = query.to_bytes()

    sock.send(query_bytes)

    resp = sock.recv(1024)

    resp_packet = DNSPacket.parse(resp)
    assert resp_packet.header.an_count > 0

    print(resp_packet.answers[-1].data)
finally:
    sock.close()
    print("Done")
