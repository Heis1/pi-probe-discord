from __future__ import annotations

import unittest

from pi_probe_discord.router_snmp import _decode_snmp_udp_packet


def _tlv(tag: int, value: bytes) -> bytes:
    length = len(value)
    if length < 0x80:
        return bytes([tag, length]) + value
    raw_len = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(raw_len)]) + raw_len + value


def _oid(oid: str) -> bytes:
    parts = [int(part) for part in oid.strip(".").split(".")]
    first = parts[0] * 40 + parts[1]
    encoded = bytearray([first])
    for part in parts[2:]:
        stack = [part & 0x7F]
        part >>= 7
        while part:
            stack.append(0x80 | (part & 0x7F))
            part >>= 7
        encoded.extend(reversed(stack))
    return bytes(encoded)


def _int(value: int, tag: int = 0x02) -> bytes:
    if value == 0:
        payload = b"\x00"
    else:
        payload = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if payload[0] & 0x80:
            payload = b"\x00" + payload
    return _tlv(tag, payload)


def _octet(text: str) -> bytes:
    return _tlv(0x04, text.encode("utf-8"))


def _varbind(oid: str, value_tlv: bytes) -> bytes:
    return _tlv(0x30, _tlv(0x06, _oid(oid)) + value_tlv)


class RouterSnmpTests(unittest.TestCase):
    def test_decode_snmp_udp_packet_extracts_trap_oid_and_summary(self) -> None:
        varbinds = b"".join(
            [
                _varbind(".1.3.6.1.2.1.1.3.0", _int(118332500, 0x43)),
                _varbind(".1.3.6.1.6.3.1.1.4.1.0", _tlv(0x06, _oid(".1.3.6.1.6.3.1.1.5.2"))),
                _varbind(".1.3.6.1.6.3.1.1.4.3.0", _tlv(0x06, _oid(".1.3.6.1.4.1.16972.2.10"))),
            ]
        )
        pdu = _tlv(0xA7, _int(1) + _int(0) + _int(0) + _tlv(0x30, varbinds))
        packet = _tlv(0x30, _int(1) + _octet("home-monitor") + pdu)

        decoded = _decode_snmp_udp_packet(packet)
        self.assertIsNotNone(decoded)
        trap_oid, summary = decoded or ("", "")
        self.assertEqual(trap_oid, "SNMPv2-MIB::warmStart")
        self.assertIn("community: home-monitor", summary)
        self.assertIn("uptime=", summary)
        self.assertIn("enterprise_oid=.1.3.6.1.4.1.16972.2.10", summary)


if __name__ == "__main__":
    unittest.main()
