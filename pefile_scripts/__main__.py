import argparse

import pefile_scripts

def create_cmd_parser():
    base_parser = argparse.ArgumentParser(prog='pefile_scripts',
        description='Скрипты анализа PE-файлов',
        add_help=False)
    parser = base_parser.add_argument_group(title='Параметры')
    parser.add_argument('-ct', '--compile-time',
        metavar='<путь к файлу>',
        dest='compile_time',
        help='Время компиляции PE-файла из стандартного поля TimeDateStamp')
    parser.add_argument('-cdt', '--debug-compile-time',
        metavar='<путь к файлу>',
        dest='debug_compile_time',
        help='Время компиляции PE-файла из секции DIRECTORY_ENTRY_DEBUG')
    parser.add_argument('-crt', '--delphi-compile-time',
        metavar='<путь к файлу>',
        dest='delphi_compile_time',
        help='Время компиляции PE-файла из секции RESOURCE_ENTRY_DEBUG')
    parser.add_argument('-sn', '--section-num',
        metavar='<путь к файлу>',
        dest='section_num',
        help='Число секций в PE-файле')
    parser.add_argument('-si', '--section-info',
        metavar='<путь к файлу>',
        dest='section_info',
        help='Информация о секциях PE-файла')
    parser.add_argument('-dn', '--dll-num',
        metavar='<путь к файлу>',
        dest='dll_num',
        help='Число импортируемых dll-библиотек')
    parser.add_argument('-ih', '--imphash',
        metavar='<путь к файлу>',
        dest='imphash',
        help='Значение imphash секции импорта PE-файла')
    parser.add_argument('-ii', '--import-info',
        metavar='<путь к файлу>',
        dest='import_info',
        help='Информация о секции импорта PE-файла')
    parser.add_argument('-ean', '--export-api-num',
        metavar='<путь к файлу>',
        dest='export_api_num',
        help='Число экспортируемых функций')
    parser.add_argument('-edn', '--export-dll-name',
        metavar='<путь к файлу>',
        dest='export_dll_name',
        help='Название библиотеки')
    parser.add_argument('-ei', '--export-info',
        metavar='<путь к файлу>',
        dest='export_info',
        help='Информация о секции экспорта PE-файла')
    parser.add_argument('-h', '--help',
        action='help',
        help='Выводит справку по программе')
    parser.add_argument('-v', '--version',
        action='version',
        help='Выводит информацию о версии программы',
        version='pefile_scripts ' + pefile_scripts.__version__)
    return base_parser

def main(parser):
    try:
        if parser.parse_args().compile_time:
            print('Время компиляции PE-файла: ' +
                pefile_scripts.get_compile_time(
                    parser.parse_args().compile_time))
        elif parser.parse_args().debug_compile_time:
            print('Время компиляции PE-файла: ' +
                pefile_scripts.get_debug_compile_time(
                    parser.parse_args().debug_compile_time))
        elif parser.parse_args().delphi_compile_time:
            print('Время компиляции PE-файла: ' +
                pefile_scripts.get_delphi_compile_time(
                    parser.parse_args().delphi_compile_time))
        elif parser.parse_args().section_num:
            print('Число секций в PE-файле: ' +
                str(pefile_scripts.get_section_num(
                    parser.parse_args().section_num)))
        elif parser.parse_args().section_info:
            for section_entry in pefile_scripts.get_section_info(parser.parse_args().section_info):
                print(section_entry['name'])
                print('\tCharacteristics:', section_entry['characteristics'])
                print('\tMD5-хэш секции:', section_entry['MD5hash'])
                print('\tЭнтропия секции:', section_entry['entropy'])
        elif parser.parse_args().dll_num:
            print('Число импортируемых dll-библиотек: ' +
                str(pefile_scripts.get_dll_num(
                    parser.parse_args().dll_num)))
        elif parser.parse_args().imphash:
            print('Значение imphash секции импорта PE-файла: ' +
                pefile_scripts.get_imphash(parser.parse_args().imphash))
        elif parser.parse_args().import_info:
            for import_entry in pefile_scripts.get_import_info(parser.parse_args().import_info):
                print('Из', import_entry['dll'], 'импортируются:')
                for api_entry in import_entry['api']:
                    print('\t', api_entry)
        elif parser.parse_args().export_api_num:
            print('Число экспортируемых функций: ' +
                str(pefile_scripts.get_export_api_num(
                    parser.parse_args().export_api_num)))
        elif parser.parse_args().export_dll_name:
            print('Название библиотеки: ' +
                pefile_scripts.get_export_dll_name(
                    parser.parse_args().export_dll_name))
        elif parser.parse_args().export_info:
            for export_entry in pefile_scripts.get_export_info(parser.parse_args().export_info):
                print('Имя экспортируемой функции:', export_entry['api'])
                print('\t Номер (ординал):', export_entry['ordinal'])
                print('\t RVA-адрес:', export_entry['rva'])
        else:
            parser.print_help()
    except pefile_scripts.PEfileScriptsError as err:
        print(err)

if __name__ == '__main__':
    main(create_cmd_parser())
    