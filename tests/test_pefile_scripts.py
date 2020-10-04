import unittest
import pytest

import pefile_scripts

TEST_FILE = 'test_file/test_file.exe'
TEST_TIME = '04-10-2020 17:56:39'
TEST_DLL_NUM = 2
TEST_SECTION_NUM = 3

class TestPefileScripts(unittest.TestCase):
    def test_get_compilation_time(self):
        self.assertEqual(pefile_scripts.get_compile_time(TEST_FILE),
            TEST_TIME)

    def test_get_section_num(self):
        self.assertEqual(pefile_scripts.get_section_num(TEST_FILE),
            TEST_SECTION_NUM)

    def test_get_dll_num(self):
        self.assertEqual(pefile_scripts.get_dll_num(TEST_FILE),
            TEST_DLL_NUM)
