import json
import unittest
from io import StringIO
from unittest.mock import MagicMock, mock_open, patch

from smbls.report import (
    hosts,
    hosts_print_error,
    hosts_print_os,
    hosts_print_shares,
    hosts_print_signing,
    hosts_print_smbver,
    hosts_select_admin,
    hosts_select_error,
    pretty_host,
    report,
    shares,
    shares_print_contents,
    shares_print_dacl,
    shares_print_errors,
    shares_print_readable,
    shares_print_remark,
    shares_print_type,
    shares_print_writable,
    shares_select_readable,
    shares_select_writable,
)


class TestReportHelpers(unittest.TestCase):
    def test_pretty_host(self) -> None:
        scan_data = {
            "1.2.3.4": {"info": {"getServerName": "HOSTA", "getRemoteName": "REMOTE"}},
            "1.2.3.5": {"info": {"getServerName": "\0", "getRemoteName": "REMOTE"}},
            "1.2.3.6": {"info": {"getServerName": "\0", "getRemoteName": "\0"}},
        }
        self.assertEqual(pretty_host("1.2.3.4", scan_data), "HOSTA")
        self.assertEqual(pretty_host("1.2.3.5", scan_data), "REMOTE")
        self.assertEqual(pretty_host("1.2.3.6", scan_data), "1.2.3.6")

    def test_host_selectors_and_printers(self) -> None:
        host_ok = {
            "shares": [
                {"name": "C$", "read_access": True},
                {"name": "other", "read_access": False},
            ],
            "info": {
                "getServerOS": "Windows",
                "isSigningRequired": True,
                "getDialect": "0x311",
            },
        }
        host_err = {"errtype": "auth", "error": "STATUS_ACCESS_DENIED"}
        self.assertTrue(hosts_select_admin(host_ok))
        self.assertFalse(hosts_select_admin({"shares": []}))
        self.assertTrue(hosts_select_error(host_err))
        self.assertFalse(hosts_select_error(host_ok))
        self.assertEqual(hosts_print_os(host_ok), "Windows")
        self.assertEqual(hosts_print_signing(host_ok), "True")
        self.assertEqual(hosts_print_smbver(host_ok), "0x311")
        self.assertEqual(hosts_print_error(host_err), "auth: STATUS_ACCESS_DENIED")
        self.assertEqual(hosts_print_error(host_ok), "-")
        # When shares missing, should render empty list
        self.assertEqual(hosts_print_shares({}), "[]")

    def test_share_selectors_and_printers(self) -> None:
        share = {
            "name": "Public",
            "type": "DISKTREE",
            "remark": "Docs",
            "read_access": True,
            "write_access": False,
            "contents": ["a.txt"],
            "dacl": ["ALLOWED,Users,GENERIC_READ"],
            "errors": [],
        }
        self.assertTrue(shares_select_readable(share))
        self.assertFalse(shares_select_writable(share))
        self.assertEqual(shares_print_contents(share), "['a.txt']")
        self.assertEqual(shares_print_dacl(share), "['ALLOWED,Users,GENERIC_READ']")
        self.assertEqual(shares_print_remark(share), "Docs")
        self.assertEqual(shares_print_errors(share), "[]")
        self.assertEqual(shares_print_type(share), "DISKTREE")
        self.assertEqual(shares_print_readable(share), "True")
        self.assertEqual(shares_print_writable(share), "False")
        # Defaults when keys missing
        self.assertEqual(shares_print_remark({}), "-")
        self.assertEqual(shares_print_type({}), "-")
        self.assertEqual(shares_print_errors({}), "[]")
        self.assertEqual(shares_print_readable({}), "not tested")
        self.assertEqual(shares_print_writable({}), "not tested")


class TestReportCLI(unittest.TestCase):
    def _json_scan(self) -> str:
        return json.dumps(
            {
                "version": "1.2.3",
                "version_tuple": [1, 2, 3],
                "data": {
                    "10.0.0.1": {
                        "info": {
                            "getServerName": "HOST1",
                            "getServerOS": "Windows",
                            "isSigningRequired": False,
                            "getDialect": "0x302",
                        },
                        "shares": [
                            {
                                "name": "C$",
                                "type": "DISKTREE",
                                "read_access": True,
                                "write_access": True,
                                "contents": ["file"],
                                "dacl": ["ALLOWED,Administrators,GENERIC_ALL"],
                                "remark": "C",
                            }
                        ],
                    }
                },
            }
        )

    @patch("smbls.report.stderr", new_callable=StringIO)
    @patch("sys.stdout", new_callable=StringIO)
    def test_list_args(self, stdout: StringIO, stderr: StringIO) -> None:
        with patch("sys.argv", ["smblsreport", "-f", "f.json", "hosts", "-s", "list"]):
            with patch(
                "argparse.FileType",
                lambda _: MagicMock(
                    return_value=mock_open(read_data=self._json_scan())
                ),
            ):
                report()
        self.assertIn("admin", stdout.getvalue())
        self.assertEqual("", stderr.getvalue())

        stdout.seek(0), stdout.truncate(0)
        stderr.seek(0), stderr.truncate(0)
        with patch(
            "sys.argv",
            ["smblsreport", "-f", "f.json", "shares", "-p", "list"],
        ):
            with patch(
                "argparse.FileType",
                lambda _: MagicMock(
                    return_value=mock_open(read_data=self._json_scan())
                ),
            ):
                report()
        self.assertIn("contents", stdout.getvalue())
        self.assertEqual("", stderr.getvalue())

        # Both list flags should error
        stdout.seek(0), stdout.truncate(0)
        stderr.seek(0), stderr.truncate(0)
        with patch(
            "sys.argv",
            ["smblsreport", "-f", "f.json", "hosts", "-s", "list", "-p", "list"],
        ):
            with patch(
                "argparse.FileType",
                lambda _: MagicMock(
                    return_value=mock_open(read_data=self._json_scan())
                ),
            ):
                with patch("builtins.exit") as exit_mock:
                    report()
                    exit_mock.assert_called_once()
        self.assertIn("error: pass only one list argument at a time", stderr.getvalue())

    @patch("smbls.report.stderr", new_callable=StringIO)
    def test_invalid_args_and_missing_file(self, stderr: StringIO) -> None:
        with patch("sys.argv", ["smblsreport", "hosts", "-s", "bad"]):
            report()
        self.assertIn("error: invalid select argument", stderr.getvalue())

        stderr.seek(0), stderr.truncate(0)
        with patch("sys.argv", ["smblsreport", "hosts", "-p", "bad"]):
            report()
        self.assertIn("error: invalid print argument", stderr.getvalue())

        stderr.seek(0), stderr.truncate(0)
        with patch("sys.argv", ["smblsreport", "hosts"]):
            report()
        self.assertIn("error: must pass -f file", stderr.getvalue())

    @patch("smbls.report.stderr", new_callable=StringIO)
    @patch("sys.stdout", new_callable=StringIO)
    def test_metadata_hosts_and_shares(
        self, stdout: StringIO, stderr: StringIO
    ) -> None:
        # metadata
        with (
            patch("sys.argv", ["smblsreport", "-f", "f.json", "metadata"]),
            patch(
                "argparse.FileType",
                MagicMock(return_value=mock_open(read_data=self._json_scan())),
            ),
        ):
            report()
        out = stdout.getvalue()
        self.assertIn("version 1.2.3", out)
        self.assertIn("version_tuple [1, 2, 3]", out)
        self.assertIn("warning: installed version", stderr.getvalue())

        # hosts
        stdout.seek(0), stdout.truncate(0)
        with (
            patch(
                "sys.argv",
                [
                    "smblsreport",
                    "-f",
                    "f.json",
                    "hosts",
                    "-s",
                    "noerror",
                    "-p",
                    "smbver,shares",
                ],
            ),
            patch(
                "argparse.FileType",
                MagicMock(return_value=mock_open(read_data=self._json_scan())),
            ),
        ):
            report()
        out = stdout.getvalue().strip().split("\t")
        self.assertEqual(out[0], "10.0.0.1")
        self.assertEqual(out[1], "HOST1")
        self.assertEqual(out[2], "0x302")
        self.assertTrue(out[3].startswith("["))

        # shares
        stdout.seek(0), stdout.truncate(0)
        with (
            patch(
                "sys.argv",
                [
                    "smblsreport",
                    "-f",
                    "f.json",
                    "shares",
                    "-s",
                    "readable",
                    "-p",
                    "type,readable,writable,contents,dacl,remark,errors",
                ],
            ),
            patch(
                "argparse.FileType",
                MagicMock(return_value=mock_open(read_data=self._json_scan())),
            ),
        ):
            report()
        out = stdout.getvalue().strip().split("\t")
        self.assertEqual(out[0], "10.0.0.1")
        self.assertEqual(out[1], "HOST1")
        self.assertEqual(out[2], "'C$'")
        self.assertEqual(out[3], "DISKTREE")
        self.assertEqual(out[4], "True")
        self.assertEqual(out[5], "True")
        self.assertIn("['file']", out[6])
        self.assertIn("ALLOWED,Administrators,GENERIC_ALL", out[7])
        self.assertEqual(out[8], "C")
        self.assertIn("[]", out[9])


class TestReportAdditional(unittest.TestCase):
    def _scan_with_share(self, name: str = "My Share") -> dict:
        return {
            "version": "1.2.3",
            "version_tuple": [1, 2, 3],
            "data": {
                "10.0.0.2": {
                    "info": {
                        "getServerName": "HOST2",
                        "getServerOS": "Windows",
                        "isSigningRequired": False,
                        "getDialect": "0x302",
                    },
                    "shares": [
                        {
                            "name": name,
                            "type": "DISKTREE",
                            "read_access": True,
                            "write_access": False,
                        }
                    ],
                }
            },
        }

    def test_hosts_print_shares_lists_names(self) -> None:
        host = {
            "shares": [
                {"name": "C$", "read_access": True},
                {"name": "Public", "read_access": True},
            ]
        }
        self.assertEqual(hosts_print_shares(host), "[C$, Public]")

    def test_hosts_output_without_print_args(self) -> None:
        scan = self._scan_with_share()
        with patch("sys.stdout", new_callable=StringIO) as stdout:
            hosts(scan, select_args=[], print_args=[])
        # Expect two columns: host and pretty host
        line = stdout.getvalue().strip()
        self.assertEqual(line, "10.0.0.2\tHOST2")

    def test_shares_output_quotes_share_name(self) -> None:
        scan = self._scan_with_share("Share With Space")
        with patch("sys.stdout", new_callable=StringIO) as stdout:
            shares(scan, select_args=["readable"], print_args=["type"])
        # Expect: host, pretty host, quoted share name, then type
        line = stdout.getvalue().strip()
        self.assertEqual(
            line, "10.0.0.2\tHOST2\t'" + "Share With Space" + "'\tDISKTREE"
        )

    def test_hosts_select_error_filters(self) -> None:
        scan = json.loads(json.dumps(self._scan_with_share()))
        # Inject an error host alongside a good one
        scan["data"]["10.0.0.3"] = {"errtype": "conn", "error": "timeout"}
        with patch("sys.stdout", new_callable=StringIO) as stdout:
            hosts(scan, select_args=["error"], print_args=["error"])
        self.assertEqual(stdout.getvalue().strip(), "10.0.0.3\t10.0.0.3\tconn: timeout")
        with patch("sys.stdout", new_callable=StringIO) as stdout:
            hosts(
                scan, select_args=["noerror"], print_args=["smbver"]
            )  # only good host
        self.assertTrue(stdout.getvalue().startswith("10.0.0.2\tHOST2\t0x302"))


if __name__ == "__main__":
    unittest.main()
