import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('web_firewall', Path(__file__).with_name('web_firewall.py'))
firewall = importlib.util.module_from_spec(spec); spec.loader.exec_module(firewall)


class FirewallTests(unittest.TestCase):
    def test_only_missing_owned_rule_is_added_without_flush_or_policy_changes(self):
        def observed(command,**kwargs):
            missing=(command[0]=='/usr/sbin/iptables' and '-C' in command and command[-len(firewall.RULE):]==firewall.RULE)
            return subprocess.CompletedProcess(command,1 if missing else 0)
        with patch.object(firewall.os,'geteuid',return_value=0),patch.object(firewall.shutil,'which',side_effect=lambda n:'/usr/sbin/'+n),patch.object(firewall.subprocess,'run',side_effect=observed) as run:
            firewall.main()
        commands=[c.args[0] for c in run.call_args_list]
        inserts=[c for c in commands if '-I' in c]
        self.assertEqual(inserts,[['/usr/sbin/iptables','-w','5','-t','filter','-I','INPUT','1',*firewall.RULE]])
        for name in ('iptables','ip6tables'):
            self.assertIn(['/usr/sbin/'+name,'-w','5','-t','filter','-C','INPUT',*firewall.HTTP3_RULE],commands)
        self.assertIn(['/usr/sbin/iptables','-w','5','-t','nat','-C','PREROUTING',*firewall.ADMIN_H3_TUN_RULE],commands)
        self.assertFalse(any('-F' in c or '-P' in c for c in commands))

    def test_inspection_error_does_not_change_rules(self):
        with patch.object(firewall.os, 'geteuid', return_value=0), patch.object(firewall.shutil, 'which', return_value='/usr/sbin/iptables'), patch.object(firewall.subprocess, 'run', return_value=subprocess.CompletedProcess([], 2)) as run:
            with self.assertRaises(ValueError): firewall.main()
        self.assertEqual(run.call_count, 1)


if __name__ == '__main__': unittest.main()
