import unittest
import pytest

import pefile_scripts

TEST_FILE = 'test_file/test_file.exe'
TEST_TIME = '04-10-2020 17:56:39'
TEST_DLL_NUM = 2
TEST_SECTION_NUM = 3
TEST_SECTION_INFO = [
    {'name': '.data\x00\x00\x00',
     'characteristics': '0xc0000040',
     'MD5hash': 'ee0b1d14c2c48bae3449886ed3e145f1',
     'entropy': 0.8943970235234769},
    {'name': '.text\x00\x00\x00',
     'characteristics': '0x60000020',
     'MD5hash': '7d1ba4184979a4f673e9cbd984670e5f',
     'entropy': 0.8069682857570428},
    {'name': '.idata\x00\x00',
     'characteristics': '0xc0000040',
     'MD5hash': '7b34092c2ff0b9c558d62480a5748a26',
     'entropy': 1.1225023163920302}
]
TEST_IMPORT_INFO = [
    {'dll': 'KERNEL32.DLL',
     'api': ['ExitProcess']},
    {'dll': 'USER32.DLL',
     'api': ['MessageBoxA']}
]
TEST_IMPHASH = '98c88d882f01a3f6ac1e5f7dfd761624'
class TestPefileScripts(unittest.TestCase):
    def test_get_compilation_time(self):
        self.assertEqual(pefile_scripts.get_compile_time(TEST_FILE),
            TEST_TIME)

    def test_get_section_num(self):
        self.assertEqual(pefile_scripts.get_section_num(TEST_FILE),
            TEST_SECTION_NUM)

    def test_get_section_info(self):
        self.assertEqual(pefile_scripts.get_section_info(TEST_FILE),
            TEST_SECTION_INFO)

    def test_get_dll_num(self):
        self.assertEqual(pefile_scripts.get_dll_num(TEST_FILE),
            TEST_DLL_NUM)

    def test_get_imphash(self):
        self.assertEqual(pefile_scripts.get_imphash(TEST_FILE),
            TEST_IMPHASH)

    def test_get_import_info(self):
        self.assertEqual(pefile_scripts.get_import_info(TEST_FILE),
            TEST_IMPORT_INFO)
