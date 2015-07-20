import os
import logging
from unittest import TestCase
from adplugins.adcommon import FileOutputClass
class TestFileOutputClass(TestCase):
    def test_OpenWithOutputDirectory(self):
        outputFile = FileOutputClass(os.path.join(os.getenv('temp'),'rajesh'), 'floatingdrivers')
        if outputFile.Open():
            outputFile.Close()

    def test_OpenWithoutOutputDirectory(self):
        outputFile = FileOutputClass(None, 'floatingdrivers')
        if outputFile.Open():
            outputFile.Close()