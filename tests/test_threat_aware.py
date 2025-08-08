import mock
from unittest import TestCase
from src import threat_aware


class TestThreatAware(TestCase):
    def setUp(self):
        self.url_list = [""]
        self.api_key = "432fb4158186f0c8268813741939239a"

    def test_scan_inputs(self):
        threat_aware_obj = threat_aware.ThreatAware(
            self.url_list, self.api_key)

        threat_aware_obj.scan_inputs()
