import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import common
import diagnostics
import make_client_configs as clients


class ConfigurationTests(unittest.TestCase):
    def test_reject_ssh_option_injection(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "project.json"
            p.write_text(json.dumps({"server_ipv4":"203.0.113.10", "ssh_target":"-oProxyCommand=anything"}))
            with patch.dict(os.environ, {"VPS_PROXY_CONFIG":str(p)}):
                with self.assertRaises(ValueError):
                    common.load_settings()

    def test_reject_wrong_address_family(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "project.json"
            p.write_text(json.dumps({"server_ipv4":"2001:db8::10", "ssh_target":"root@example.net"}))
            with patch.dict(os.environ, {"VPS_PROXY_CONFIG":str(p)}):
                with self.assertRaises(ValueError):
                    common.load_settings()

    def test_ipv6_uri_and_client_specific_fields(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            out.joinpath("optimized-nodes.json").write_text(json.dumps({"nodes":[{
                "name":"VPS-IPv6", "type":"hysteria2", "server":"2001:db8::10", "port":8443,
                "sni":"203.0.113.10", "obfs_password":"sample-obfs-key", "download_mbps":50, "upload_mbps":10}]}))
            with patch.object(clients, "OUT", out), patch.object(clients, "load_settings", return_value={"surge_interface":"en0"}):
                nodes, uris = clients.build_nodes({"server":"203.0.113.10", "port":443, "password":"test-password"})
                surge = clients.surge_node(nodes[0])
                sr = clients.surge_node(nodes[0], False)
                mihomo = clients.mihomo_node(nodes[0])
            self.assertIn("@[2001:db8::10]:8443", uris[0])
            self.assertIn("insecure=0", uris[0])
            self.assertIn("obfs=salamander", uris[0])
            self.assertIn("hysteria2, 2001:db8::10,", surge)
            self.assertNotIn("[2001:db8", surge)
            self.assertIn("salamander-password=", surge)
            self.assertIn("interface=en0", surge)
            self.assertNotIn("interface=", sr)
            self.assertNotIn("upload-bandwidth=", surge)
            self.assertEqual(mihomo["obfs"], "salamander")
            self.assertFalse(mihomo["skip-cert-verify"])
            self.assertTrue(any(n["server"] == "203.0.113.10" for n in nodes))

    def test_reject_node_line_injection(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            out.joinpath("optimized-nodes.json").write_text(json.dumps({"nodes":[{
                "name":"bad\n[Rule]", "type":"trojan", "server":"2001:db8::10", "port":443}]}))
            with patch.object(clients, "OUT", out):
                with self.assertRaises(ValueError):
                    clients.build_nodes({"server":"203.0.113.10", "port":443, "password":"test-password"})

    def test_private_output_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "credentials.json"
            clients.private_write(p, "sample")
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)


class ProtocolTests(unittest.TestCase):
    def test_varint_round_trip(self):
        a, b = socket.socketpair()
        try:
            for value in [0,1,127,128,255,65535,2**31-1]:
                a.sendall(diagnostics._varint(value))
                self.assertEqual(diagnostics._read_varint(b), value)
        finally:
            a.close(); b.close()

    def test_reject_malformed_varint_and_oversized_packet(self):
        a, b = socket.socketpair()
        try:
            a.sendall(b"\x80"*5)
            with self.assertRaises(ValueError): diagnostics._read_varint(b)
            a.sendall(diagnostics._varint(2_000_000))
            with self.assertRaises(ValueError): diagnostics._read_packet(b)
        finally:
            a.close(); b.close()

    def test_proxy_credentials_not_accepted_on_command_line(self):
        with self.assertRaises(ValueError): diagnostics._parse_proxy("http://user:password@example.net:8080")
        self.assertEqual(diagnostics._parse_proxy("http://127.0.0.1:6152"), ("127.0.0.1",6152))


if __name__ == "__main__":
    unittest.main()
