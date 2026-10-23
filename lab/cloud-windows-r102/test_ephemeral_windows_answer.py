"""R102 no-OS-mutation XML fixture tests. Does not install or boot Windows."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from ephemeral_windows_answer import (
    ALLOWED_EDITION, UnsafeAnswerFile, generate, write_one_run_answer,
)
NS = {"u": "urn:schemas-microsoft-com:unattend"}


class R102EphemeralAnswerSafetyTests(unittest.TestCase):
    def test_dynamic_secret_and_no_security_bypass(self):
        xml, secret = generate(2, edition=ALLOWED_EDITION)
        self.assertGreater(len(secret), 30)
        self.assertTrue(secret.startswith("A7!"))
        root = ET.fromstring(xml)
        password = root.find(".//u:AdministratorPassword/u:Value", NS)
        self.assertEqual(password.text, secret)
        self.assertEqual(root.find(".//u:AdministratorPassword/u:PlainText", NS).text,
                         "true")
        self.assertIn(b"/IMAGE/INDEX", xml)
        self.assertNotIn(b"AutoLogon", xml)
        self.assertNotIn(b"RunSynchronous", xml)
        self.assertNotIn(b"FirstLogonCommands", xml)
        self.assertNotIn(b"Bypass", xml)
        self.assertNotIn(b"ProductKey", xml)
        self.assertNotIn(b"DriverPaths", xml)
        self.assertNotIn(b"Firewall", xml)
        self.assertNotIn(b"WireGuard", xml)
        self.assertNotIn(b"WFP", xml)

    def test_ephemeral_secret_changes_between_attempts(self):
        _, first = generate(2, edition=ALLOWED_EDITION)
        _, second = generate(2, edition=ALLOWED_EDITION)
        self.assertNotEqual(first, second)

    def test_refuse_unreviewed_image_selection(self):
        for val in (0, 9, -1, True, "2", None):
            with self.subTest(val=val), self.assertRaises(UnsafeAnswerFile):
                generate(val, edition=ALLOWED_EDITION)
        with self.assertRaises(UnsafeAnswerFile):
            generate(2, edition="Windows Server 2025 DataCenter retail")

    def test_uefi_gpt_exact_disk_only(self):
        root = ET.fromstring(generate(2, edition=ALLOWED_EDITION)[0])
        self.assertEqual([n.text for n in root.findall(".//u:DiskID", NS)],
                         ["0", "0"])
        self.assertEqual([n.text for n in root.findall(".//u:CreatePartition/u:Type", NS)],
                         ["EFI", "MSR", "Primary"])
        self.assertEqual(root.find(".//u:InstallTo/u:PartitionID", NS).text, "3")
        self.assertEqual(root.find(".//u:AcceptEula", NS).text, "true")

    def test_refuse_output_outside_runner_or_existing_target(self):
        with TemporaryDirectory() as root:
            temp = Path(root)
            env = {"RUNNER_TEMP": root, "GITHUB_ACTIONS": "true",
                   "RUNNER_ENVIRONMENT": "github-hosted",
                   "RUNNER_OS": "Linux"}
            with patch.dict(os.environ, env):
                with self.assertRaises(UnsafeAnswerFile):
                    write_one_run_answer(2, edition=ALLOWED_EDITION,
                                         output=temp/"other.xml")
                with self.assertRaises(UnsafeAnswerFile):
                    write_one_run_answer(2, edition=ALLOWED_EDITION,
                                         output=temp/"sub"/"Autounattend.xml")
                with patch.dict(os.environ, {"RUNNER_ENVIRONMENT": "self-hosted"}):
                    with self.assertRaises(UnsafeAnswerFile):
                        write_one_run_answer(2, edition=ALLOWED_EDITION,
                                             output=temp/"Autounattend.xml")
                write_one_run_answer(2, edition=ALLOWED_EDITION,
                                     output=temp/"Autounattend.xml")
                self.assertEqual((temp/"Autounattend.xml").stat().st_mode & 0o777,
                                 0o600)
                with self.assertRaises(UnsafeAnswerFile):
                    write_one_run_answer(2, edition=ALLOWED_EDITION,
                                         output=temp/"Autounattend.xml")


if __name__ == "__main__":
    unittest.main()
