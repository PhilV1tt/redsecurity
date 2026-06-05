import unittest

from besecured.checks.common import (
    ListeningPort,
    _decode_proc_address,
    _lsof_listeners_from_text,
    _netstat_listeners_from_text,
    _port_scope,
    _ss_listeners_from_text,
    _windows_netstat_listeners_from_text,
    unavailable_finding,
)


class CommonParserTests(unittest.TestCase):
    def test_proc_address_decodes_loopback_and_wildcard(self):
        self.assertEqual(_decode_proc_address("0100007F"), "127.0.0.1")
        self.assertEqual(_decode_proc_address("00000000"), "0.0.0.0")

    def test_port_scope_distinguishes_loopback(self):
        self.assertEqual(_port_scope([ListeningPort(8080, "127.0.0.1")]), "loopback")
        self.assertEqual(_port_scope([ListeningPort(8080, "0.0.0.0")]), "all interfaces")
        self.assertEqual(_port_scope([ListeningPort(8080, "127.0.0.1%lo")]), "loopback")

    def test_port_scope_does_not_ignore_unknown_addresses(self):
        listeners = [ListeningPort(8080, "127.0.0.1"), ListeningPort(8080, "")]

        self.assertEqual(_port_scope(listeners), "unknown")

    def test_lsof_parser_keeps_loopback_address(self):
        text = """COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
Python  1234 phil    7u  IPv4  12345      0t0  TCP localhost:8080 (LISTEN)
"""
        listeners = _lsof_listeners_from_text(text)

        self.assertEqual(listeners[0].port, 8080)
        self.assertEqual(listeners[0].address, "127.0.0.1")

    def test_windows_netstat_parser_keeps_bind_address(self):
        text = """
  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       888
  TCP    127.0.0.1:8080         0.0.0.0:0              LISTENING       999
"""
        listeners = _windows_netstat_listeners_from_text(text)

        self.assertEqual([(item.port, item.address) for item in listeners], [(3389, "0.0.0.0"), (8080, "127.0.0.1")])

    def test_netstat_fallback_keeps_multiple_addresses_per_port(self):
        text = """
tcp4       0      0  127.0.0.1.8080         *.*                    LISTEN
tcp4       0      0  *.8080                 *.*                    LISTEN
"""
        listeners = _netstat_listeners_from_text(text, "LISTEN")

        self.assertEqual(len(listeners), 2)
        self.assertEqual([(item.port, item.address) for item in listeners], [(8080, "127.0.0.1"), (8080, "*")])

    def test_ss_parser_handles_wildcard_and_loopback(self):
        text = """
LISTEN 0      4096     127.0.0.53%lo:53      0.0.0.0:*
LISTEN 0      128      0.0.0.0:22            0.0.0.0:*
"""
        listeners = _ss_listeners_from_text(text)

        self.assertEqual([(item.port, item.address) for item in listeners], [(22, "0.0.0.0"), (53, "127.0.0.53%lo")])

    def test_unavailable_finding_uses_skip(self):
        finding = unavailable_finding("Firewall", "Firewall Check", "tool missing", "Check manually.")

        self.assertEqual(finding.status, "SKIP")
        self.assertIn("tool missing", finding.detail)


if __name__ == "__main__":
    unittest.main()
