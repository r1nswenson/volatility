import logging
from unittest import TestCase
from adplugins.adcommon import ExpandPath

class TestCommonUtils(TestCase):
    def test_ExpandPath(self):
        path = "\SystemRoot\system32\hal.dll"
        expandedPath = ExpandPath(path)
        self.assertTrue(not expandedPath.startswith('\\SystemRoot'), 'test failed')
