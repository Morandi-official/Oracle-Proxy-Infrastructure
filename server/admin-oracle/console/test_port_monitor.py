from datetime import datetime, timezone
from unittest import TestCase

from .port_monitor import format_status


class PortMonitorTests(TestCase):
    def test_platform_results_are_independent_and_stale_results_are_unknown(self):
        now = 1_790_000_000

        def report(name, outcome, age, app='github-actions'):
            return {'name': name, 'conclusion': outcome, 'app': {'slug': app},
                    'completed_at': datetime.fromtimestamp(now-age, timezone.utc).isoformat()}

        rows = format_status([
            report('port-monitor/windows/443', 'success', 20),
            report('port-monitor/android/443', 'failure', 15),
            report('port-monitor/windows/8443', 'success', 3000),
            report('port-monitor/android/8443', 'neutral', 0),
            report('port-monitor/windows/51820', 'success', 0, app='untrusted'),
            report('port-monitor/android/51820', 'success', -100),
            {'name': 'port-monitor/windows/443'},
        ], now)['rows']
        result = {row['port']: row for row in rows}
        self.assertEqual(result[443]['windows']['result'], 'success')
        self.assertEqual(result[443]['android']['result'], 'failure')
        self.assertIsNone(result[8443]['windows'])
        self.assertEqual(result[8443]['android']['result'], 'error')
        self.assertIsNone(result[51820]['windows'])
        self.assertIsNone(result[51820]['android'])
