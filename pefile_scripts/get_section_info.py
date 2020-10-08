"""
Модуль, реализующий функции получения информацию о секциях PE-файла.

Функции:
    get_section_num(): Функция возвращает число секций в PE-файле.
    get_section_info(): Функция возвращает информацию о секциях PE-файла.
"""

import pefile
from .pefile_scripts_exception import PEfileScriptsError

def get_section_num(file_path):
    """
    Функция возвращает число секций в PE-файле.
    
    Аргументы:
      file_path: Путь к файлу (в виде строки).

    Возвращаемое значение:
      Число секций в PE-файле.

    Исключения:
      PEfileScriptsError('Запрашиваемый файл не найден'): В случае отсутствия
        проверяемого файла.
      PEfileScriptsError('Запрашиваемый файл не является PE-файлом'): В случае,
        когда проверяемый файл не является PE-файлом.
    """
    try:
        pe = pefile.PE(file_path)
    except FileNotFoundError as err:
        raise PEfileScriptsError('Файл не найден') from err
    except pefile.PEFormatError as err:
        raise PEfileScriptsError('Файл не является PE-файлом') from err
    return len(pe.sections)

def get_section_info(file_path):
    """
    Функция возвращает информацию о секциях PE-файла.

    Аргументы:
      file_path: Путь к файлу (в виде строки).

    Возвращаемое значение:
      Информация о секциях PE-файла в виде списка объектов типа 'dict' с
      элементами:
      - 'name' - имя секции;
      - 'characteristics' - значение поля 'Characteristics';
      - 'MD5hash' - значение md5-хэша от секции;
      - 'entropy' - значение энтропии секции.

    Исключения:
      PEfileScriptsError('Запрашиваемый файл не найден'): В случае отсутствия
        проверяемого файла.
      PEfileScriptsError('Запрашиваемый файл не является PE-файлом'): В случае,
        когда проверяемый файл не является PE-файлом.
    """
    try:
        pe = pefile.PE(file_path)
    except FileNotFoundError as err:
        raise PEfileScriptsError('Файл не найден') from err
    except pefile.PEFormatError as err:
        raise PEfileScriptsError('Файл не является PE-файлом') from err
    section_info = []
    for section_entry in pe.sections:
        section_info.append(dict(
            name=section_entry.Name.decode('utf-8'),
            characteristics=hex(section_entry.Characteristics),
            MD5hash=section_entry.get_hash_md5(),
            entropy=section_entry.get_entropy()))
    return section_info
