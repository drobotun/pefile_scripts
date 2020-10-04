import unittest
import pytest

import pefile_scripts

TEST_EXE = 'test_file/test_exe.exe'
TEST_DLL = 'test_file/test_dll.dll'
TEST_FILE_NO_IMPORT = 'test_file/test_file_no_import.exe'
TEST_FILE_NO_PE = 'test_file/test_file_no_pe.exe'
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
TEST_EXPORT_DLL_NAME = 'test_dll.dll'
TEST_EXPORT_API_NUM = 1
TEST_EXPORT_INFO = [
    {'api': 'TestFunction',
     'ordinal': 1,
     'rva': 8198}
]

class TestPefileScripts(unittest.TestCase):
    def test_get_compilation_time(self):
        self.assertEqual(pefile_scripts.get_compile_time(TEST_EXE),
            TEST_TIME)
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_compile_time(TEST_FILE_NO_PE)
        self.assertTrue('Файл не является PE-файлом' in str(context.exception))
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_compile_time('')
        self.assertTrue('Файл не найден' in str(context.exception))

    def test_get_section_num(self):
        self.assertEqual(pefile_scripts.get_section_num(TEST_EXE),
            TEST_SECTION_NUM)
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_section_num(TEST_FILE_NO_PE)
        self.assertTrue('Файл не является PE-файлом' in str(context.exception))
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_section_num('')
        self.assertTrue('Файл не найден' in str(context.exception))

    def test_get_section_info(self):
        self.assertEqual(pefile_scripts.get_section_info(TEST_EXE),
            TEST_SECTION_INFO)
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_section_info(TEST_FILE_NO_PE)
        self.assertTrue('Файл не является PE-файлом' in str(context.exception))
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_section_info('')
        self.assertTrue('Файл не найден' in str(context.exception))

    def test_get_dll_num(self):
        self.assertEqual(pefile_scripts.get_dll_num(TEST_EXE),
            TEST_DLL_NUM)
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_dll_num(TEST_FILE_NO_PE)
        self.assertTrue('Файл не является PE-файлом' in str(context.exception))
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_dll_num('')
        self.assertTrue('Файл не найден' in str(context.exception))
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_dll_num(TEST_FILE_NO_IMPORT)
        self.assertTrue('Таблица импорта отсутствует' in str(context.exception))

    def test_get_imphash(self):
        self.assertEqual(pefile_scripts.get_imphash(TEST_EXE),
            TEST_IMPHASH)
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_imphash(TEST_FILE_NO_PE)
        self.assertTrue('Файл не является PE-файлом' in str(context.exception))
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_imphash('')
        self.assertTrue('Файл не найден' in str(context.exception))
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_imphash(TEST_FILE_NO_IMPORT)
        self.assertTrue('Таблица импорта отсутствует' in str(context.exception))

    def test_get_import_info(self):
        self.assertEqual(pefile_scripts.get_import_info(TEST_EXE),
            TEST_IMPORT_INFO)
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_import_info(TEST_FILE_NO_PE)
        self.assertTrue('Файл не является PE-файлом' in str(context.exception))
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_import_info('')
        self.assertTrue('Файл не найден' in str(context.exception))
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_import_info(TEST_FILE_NO_IMPORT)
        self.assertTrue('Таблица импорта отсутствует' in str(context.exception))

    def test_get_export_api_num(self):
        self.assertEqual(pefile_scripts.get_export_api_num(TEST_DLL),
            TEST_EXPORT_API_NUM)
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_export_api_num(TEST_FILE_NO_PE)
        self.assertTrue('Файл не является PE-файлом' in str(context.exception))
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_export_api_num('')
        self.assertTrue('Файл не найден' in str(context.exception))
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_export_api_num(TEST_EXE)
        self.assertTrue('Таблица экспорта отсутствует' in str(context.exception))

    def test_get_export_dll_name(self):
        self.assertEqual(pefile_scripts.get_export_dll_name(TEST_DLL),
            TEST_EXPORT_DLL_NAME)
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_export_dll_name(TEST_FILE_NO_PE)
        self.assertTrue('Файл не является PE-файлом' in str(context.exception))
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_export_dll_name('')
        self.assertTrue('Файл не найден' in str(context.exception))
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_export_dll_name(TEST_EXE)
        self.assertTrue('Таблица экспорта отсутствует' in str(context.exception))

    def test_get_export_info(self):
        print(pefile_scripts.get_export_info(TEST_DLL))
        self.assertEqual(pefile_scripts.get_export_info(TEST_DLL),
            TEST_EXPORT_INFO)
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_export_info(TEST_FILE_NO_PE)
        self.assertTrue('Файл не является PE-файлом' in str(context.exception))
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_export_info('')
        self.assertTrue('Файл не найден' in str(context.exception))
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_export_info(TEST_EXE)
        self.assertTrue('Таблица экспорта отсутствует' in str(context.exception))