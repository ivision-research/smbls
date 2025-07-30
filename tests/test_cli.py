import subprocess
import unittest


class TestRunningCli(unittest.TestCase):
    def test_exec_sanity(self) -> None:
        self.assertEqual(
            subprocess.run(["python", "-V"], capture_output=True).returncode,
            0,
        )

    def test_smbls(self) -> None:
        self.assertEqual(
            subprocess.run(["smbls", "-V"], capture_output=True).returncode,
            0,
        )

    def test_smblsreport(self) -> None:
        self.assertEqual(
            subprocess.run(["smblsreport", "-V"], capture_output=True).returncode,
            0,
        )
