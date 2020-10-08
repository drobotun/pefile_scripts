"""Модуль, реализующий функции получения информацию о секциb импорта PE-файла.

Функции:
    get_export_api_num(): Функция возвращает число экспортируемых функций.
    get_export_dll_name(): Функция возвращает имя библиотеки.
    get_export_info(): Функция возвращает информацию о таблице экспорта PE-файла.
"""

import pefile
from .pefile_scripts_exception import PEfileScriptsError

def get_export_api_num(file_path):
    """Функция возвращает число экспортируемых функций.

    Аргументы:
      file_path: Путь к файлу (в виде строки).

    Возвращаемое значение:
      Число экспортируемых PE-файлом функций.

    Исключения:
      PEfileScriptsError('Запрашиваемый файл не найден'): В случае отсутствия
        проверяемого файла.
      PEfileScriptsError('Запрашиваемый файл не является PE-файлом'): В случае,
        когда проверяемый файл не является PE-файлом.
      PEfileScriptsError('Таблица экспорта отсутствует'): В случае отсутствия в
        PE-файле таблицы экспорта.
    """
    try:
        pe = pefile.PE(file_path)
    except FileNotFoundError as err:
        raise PEfileScriptsError('Файл не найден') from err
    except pefile.PEFormatError as err:
        raise PEfileScriptsError('Файл не является PE-файлом') from err
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        return len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    raise PEfileScriptsError('Таблица экспорта отсутствует')

def get_export_dll_name(file_path):
    """Функция возвращает имя библиотеки.

    Аргументы:
      file_path: Путь к файлу (в виде строки).

    Возвращаемое значение:
      Строка с именем библиотеки.

    Исключения:
      PEfileScriptsError('Запрашиваемый файл не найден'): В случае отсутствия
        проверяемого файла.
      PEfileScriptsError('Запрашиваемый файл не является PE-файлом'): В случае,
        когда проверяемый файл не является PE-файлом.
      PEfileScriptsError('Таблица экспорта отсутствует'): В случае отсутствия в
        PE-файле таблицы экспорта.
    """
    try:
        pe = pefile.PE(file_path)
    except FileNotFoundError as err:
        raise PEfileScriptsError('Файл не найден') from err
    except pefile.PEFormatError as err:
        raise PEfileScriptsError('Файл не является PE-файлом') from err
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        return pe.DIRECTORY_ENTRY_EXPORT.name.decode('utf-8')
    raise PEfileScriptsError('Таблица экспорта отсутствует')

def get_export_info(file_path):
    """Функция возвращает информацию о таблице экспорта PE-файла.

    Аргументы:
      file_path: Путь к файлу (в виде строки).

    Возвращаемое значение:
      Информация об экспортируемых PE-файлом функциях в виде списка объектов
      типа 'dict' с элементами:
      - 'api' - имя функции;
      - 'ordinal' - значение ординала (номера) экспортируемой функции;
      - 'rva' - значение RVA-адреса экспортируемой функции.

    Исключения:
      PEfileScriptsError('Запрашиваемый файл не найден'): В случае отсутствия
        проверяемого файла.
      PEfileScriptsError('Запрашиваемый файл не является PE-файлом'): В случае,
        когда проверяемый файл не является PE-файлом.
      PEfileScriptsError('Таблица экспорта отсутствует'): В случае отсутствия в
        PE-файле таблицы экспорта.
    """
    try:
        pe = pefile.PE(file_path)
    except FileNotFoundError as err:
        raise PEfileScriptsError('Файл не найден') from err
    except pefile.PEFormatError as err:
        raise PEfileScriptsError('Файл не является PE-файлом') from err
    export_info = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for export_entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            export_info.append(dict(
                api=export_entry.name.decode('utf-8'),
                ordinal=export_entry.ordinal,
                rva=export_entry.address))
        return export_info
    raise PEfileScriptsError('Таблица экспорта отсутствует')
