import unittest
from unittest import mock

import pefile_scripts
from pefile_scripts.__main__ import create_cmd_parser
from pefile_scripts.__main__ import main

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

class TestPEfileScripts(unittest.TestCase):
    def test_get_compile_time(self):
        self.assertEqual(pefile_scripts.get_compile_time(TEST_EXE),
            TEST_TIME)

    def test_get_compile_time_file_no_pe(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_compile_time(TEST_FILE_NO_PE)
        self.assertTrue('Файл не является PE-файлом' in str(context.exception))

    def test_get_compile_time_file_no_found(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_compile_time('')
        self.assertTrue('Файл не найден' in str(context.exception))

    def test_get_debug_compile_time_file_no_pe(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_debug_compile_time(TEST_FILE_NO_PE)
        self.assertTrue('Файл не является PE-файлом' in str(context.exception))

    def test_get_debug_compile_time_file_no_found(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_debug_compile_time('')
        self.assertTrue('Файл не найден' in str(context.exception))

    def test_get_debug_compile_time_file_no_debug(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_debug_compile_time(TEST_EXE)
        self.assertTrue('Отсутствует секция DIRECTORY_ENTRY_DEBUG' in str(context.exception))

    def test_get_delphi_compile_time_file_no_pe(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_delphi_compile_time(TEST_FILE_NO_PE)
        self.assertTrue('Файл не является PE-файлом' in str(context.exception))

    def test_get_delphi_compile_time_file_no_found(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_delphi_compile_time('')
        self.assertTrue('Файл не найден' in str(context.exception))

    def test_get_delphi_compile_time_file_no_resource(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_delphi_compile_time(TEST_EXE)
        self.assertTrue('Отсутствует секция DIRECTORY_ENTRY_RESOURCE' in str(context.exception))

    def test_get_section_num(self):
        self.assertEqual(pefile_scripts.get_section_num(TEST_EXE),
            TEST_SECTION_NUM)

    def test_get_section_num_file_no_pe(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_section_num(TEST_FILE_NO_PE)
        self.assertTrue('Файл не является PE-файлом' in str(context.exception))

    def test_get_section_num_file_no_found(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_section_num('')
        self.assertTrue('Файл не найден' in str(context.exception))

    def test_get_section_info(self):
        self.assertEqual(pefile_scripts.get_section_info(TEST_EXE),
            TEST_SECTION_INFO)

    def test_get_section_info_file_no_pe(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_section_info(TEST_FILE_NO_PE)
        self.assertTrue('Файл не является PE-файлом' in str(context.exception))

    def test_get_section_info_file_no_found(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_section_info('')
        self.assertTrue('Файл не найден' in str(context.exception))

    def test_get_dll_num(self):
        self.assertEqual(pefile_scripts.get_dll_num(TEST_EXE),
            TEST_DLL_NUM)

    def test_get_dll_num_file_no_pe(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_dll_num(TEST_FILE_NO_PE)
        self.assertTrue('Файл не является PE-файлом' in str(context.exception))

    def test_get_dll_num_file_no_found(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_dll_num('')
        self.assertTrue('Файл не найден' in str(context.exception))

    def test_get_dll_num_file_no_import(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_dll_num(TEST_FILE_NO_IMPORT)
        self.assertTrue('Таблица импорта отсутствует' in str(context.exception))

    def test_get_imphash(self):
        self.assertEqual(pefile_scripts.get_imphash(TEST_EXE),
            TEST_IMPHASH)

    def test_get_imphash_file_no_pe(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_imphash(TEST_FILE_NO_PE)
        self.assertTrue('Файл не является PE-файлом' in str(context.exception))

    def test_get_imphash_file_no_found(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_imphash('')
        self.assertTrue('Файл не найден' in str(context.exception))

    def test_get_imphash_file_no_import(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_imphash(TEST_FILE_NO_IMPORT)
        self.assertTrue('Таблица импорта отсутствует' in str(context.exception))

    def test_get_import_info(self):
        self.assertEqual(pefile_scripts.get_import_info(TEST_EXE),
            TEST_IMPORT_INFO)

    def test_get_import_info_file_no_pe(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_import_info(TEST_FILE_NO_PE)
        self.assertTrue('Файл не является PE-файлом' in str(context.exception))

    def test_get_import_info_file_no_found(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_import_info('')
        self.assertTrue('Файл не найден' in str(context.exception))

    def test_get_import_info_file_no_import(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_import_info(TEST_FILE_NO_IMPORT)
        self.assertTrue('Таблица импорта отсутствует' in str(context.exception))

    def test_get_export_api_num(self):
        self.assertEqual(pefile_scripts.get_export_api_num(TEST_DLL),
            TEST_EXPORT_API_NUM)

    def test_get_export_api_num_file_no_pe(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_export_api_num(TEST_FILE_NO_PE)
        self.assertTrue('Файл не является PE-файлом' in str(context.exception))

    def test_get_export_api_num_file_no_found(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_export_api_num('')
        self.assertTrue('Файл не найден' in str(context.exception))

    def test_get_export_api_num_file_no_export(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_export_api_num(TEST_EXE)
        self.assertTrue('Таблица экспорта отсутствует' in str(context.exception))

    def test_get_export_dll_name(self):
        self.assertEqual(pefile_scripts.get_export_dll_name(TEST_DLL),
            TEST_EXPORT_DLL_NAME)

    def test_get_export_dll_name_file_no_pe(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_export_dll_name(TEST_FILE_NO_PE)
        self.assertTrue('Файл не является PE-файлом' in str(context.exception))

    def test_get_export_dll_name_file_no_found(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_export_dll_name('')
        self.assertTrue('Файл не найден' in str(context.exception))

    def test_get_export_dll_name_file_no_export(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_export_dll_name(TEST_EXE)
        self.assertTrue('Таблица экспорта отсутствует' in str(context.exception))

    def test_get_export_info(self):
        self.assertEqual(pefile_scripts.get_export_info(TEST_DLL),
            TEST_EXPORT_INFO)

    def test_get_export_info_file_no_pe(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_export_info(TEST_FILE_NO_PE)
        self.assertTrue('Файл не является PE-файлом' in str(context.exception))

    def test_get_export_info_file_no_found(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_export_info('')
        self.assertTrue('Файл не найден' in str(context.exception))

    def test_get_export_info_file_no_export(self):
        with self.assertRaises(pefile_scripts.PEfileScriptsError) as context:
            pefile_scripts.get_export_info(TEST_EXE)
        self.assertTrue('Таблица экспорта отсутствует' in str(context.exception))

class TestPEfileScriptsParser(unittest.TestCase):
    def setUp(self):
        self.parser = create_cmd_parser()

    def test_parser_get_time_info_ct(self):
        test_parser = self.parser.parse_args(['-ct', TEST_EXE])
        self.assertEqual(test_parser.compile_time, TEST_EXE)

    def test_parser_get_time_info_cdt(self):
        test_parser = self.parser.parse_args(['-cdt', TEST_EXE])
        self.assertEqual(test_parser.debug_compile_time, TEST_EXE)

    def test_parser_get_time_info_crt(self):
        test_parser = self.parser.parse_args(['-crt', 'test_file.exe'])
        self.assertEqual(test_parser.delphi_compile_time, 'test_file.exe')

    def test_parser_get_section_info_sn(self):
        test_parser = self.parser.parse_args(['-sn', 'test_file.exe'])
        self.assertEqual(test_parser.section_num, 'test_file.exe')

    def test_parser_get_section_info_si(self):
        test_parser = self.parser.parse_args(['-si', 'test_file.exe'])
        self.assertEqual(test_parser.section_info, 'test_file.exe')

    def test_parser_get_import_info_dn(self):
        test_parser = self.parser.parse_args(['-dn', 'test_file.exe'])
        self.assertEqual(test_parser.dll_num, 'test_file.exe')

    def test_parser_get_import_info_ih(self):
        test_parser = self.parser.parse_args(['-ih', 'test_file.exe'])
        self.assertEqual(test_parser.imphash, 'test_file.exe')

    def test_parser_get_import_info_ii(self):
        test_parser = self.parser.parse_args(['-ii', 'test_file.exe'])
        self.assertEqual(test_parser.import_info, 'test_file.exe')

    def test_parser_get_export_info_ean(self):
        test_parser = self.parser.parse_args(['-ean', 'test_file.exe'])
        self.assertEqual(test_parser.export_api_num, 'test_file.exe')

    def test_parser_get_export_info_edn(self):
        test_parser = self.parser.parse_args(['-edn', 'test_file.exe'])
        self.assertEqual(test_parser.export_dll_name, 'test_file.exe')

    def test_parser_get_export_info_ei(self):
        test_parser = self.parser.parse_args(['-ei', 'test_file.exe'])
        self.assertEqual(test_parser.export_info, 'test_file.exe')

    def test_main_ct(self):
        with unittest.mock.patch('sys.argv', [None, '-ct', TEST_EXE]):
            main(create_cmd_parser())

    def test_main_cdt(self):
        with unittest.mock.patch('sys.argv', [None, '-cdt', TEST_EXE]):
            main(create_cmd_parser())

    def test_main_crt(self):
        with unittest.mock.patch('sys.argv', [None, '-crt', TEST_EXE]):
            main(create_cmd_parser())

    def test_main_sn(self):
        with unittest.mock.patch('sys.argv', [None, '-sn', TEST_EXE]):
            main(create_cmd_parser())

    def test_main_si(self):
        with unittest.mock.patch('sys.argv', [None, '-si', TEST_EXE]):
            main(create_cmd_parser())

    def test_main_dn(self):
        with unittest.mock.patch('sys.argv', [None, '-dn', TEST_EXE]):
            main(create_cmd_parser())

    def test_main_ih(self):
        with unittest.mock.patch('sys.argv', [None, '-ih', TEST_EXE]):
            main(create_cmd_parser())

    def test_main_ii(self):
        with unittest.mock.patch('sys.argv', [None, '-ii', TEST_EXE]):
            main(create_cmd_parser())

    def test_main_ean(self):
        with unittest.mock.patch('sys.argv', [None, '-ean', TEST_DLL]):
            main(create_cmd_parser())

    def test_main_edn(self):
        with unittest.mock.patch('sys.argv', [None, '-edn', TEST_DLL]):
            main(create_cmd_parser())

    def test_main_ei(self):
        with unittest.mock.patch('sys.argv', [None, '-ei', TEST_DLL]):
            main(create_cmd_parser())

    def test_main_no_arg(self):
        with unittest.mock.patch('sys.argv', [None]):
            main(create_cmd_parser())

if __name__ == "__main__":
    unittest.main()
