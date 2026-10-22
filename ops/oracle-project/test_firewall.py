import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('web_firewall', Path(__file__).with_name('web_firewall.py'))
firewall = importlib.util.module_from_spec(spec); spec.loader.exec_module(firewall)


class FirewallTests(unittest.TestCase):
    def test_only_missing_owned_rule_is_added_without_flush_or_policy_changes(self):
        results = [subprocess.CompletedProcess([], 1), subprocess.CompletedProcess([], 0),
                   subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 0),
                   subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 0)]
        with patch.object(firewall.os, 'geteuid', return_value=0), patch.object(firewall.shutil, 'which', side_effect=lambda n:'/usr/sbin/'+n), patch.object(firewall.subprocess, 'run', side_effect=results) as run:
            firewall.main()
        commands = [c.args[0] for c in run.call_args_list]
        self.assertEqual(commands[1], ['/usr/sbin/iptables', '-w', '5', '-t', 'filter', '-I', 'INPUT', '1', *firewall.RULE])
        self.assertEqual(len(commands), 6)
        self.assertEqual(commands[2], ['/usr/sbin/iptables', '-w', '5', '-t', 'filter', '-C', 'INPUT', *firewall.QUIC_RULE])
        self.assertFalse(any('-F' in c or '-P' in c for c in commands))

    def test_inspection_error_does_not_change_rules(self):
        with patch.object(firewall.os, 'geteuid', return_value=0), patch.object(firewall.shutil, 'which', return_value='/usr/sbin/iptables'), patch.object(firewall.subprocess, 'run', return_value=subprocess.CompletedProcess([], 2)) as run:
            with self.assertRaises(ValueError): firewall.main()
        self.assertEqual(run.call_count, 1)


if __name__ == '__main__': unittest.main()
