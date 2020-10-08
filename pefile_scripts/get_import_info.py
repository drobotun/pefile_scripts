"""
Модуль, реализующий функции получения информацию о секциb импорта PE-файла.

Функции:
    get_dll_num(): Функция возвращает число импортируемых PE-файлом
      dll-библиотек.
    get_imphash(): Функция вычисляет значение imphash для PE-файла.
    get_import_info(): Функция возвращает информацию о таблице импорта PE-файла.
"""
import pefile
from .pefile_scripts_exception import PEfileScriptsError

def get_dll_num(file_path):
    """
    Функция возвращает число импортируемых PE-файлом dll-библиотек.

    Аргументы:
      file_path: Путь к файлу (в виде строки).

    Возвращаемое значение:
      Число импортируемых PE-файлом dll-библиотек.

    Исключения:
      PEfileScriptsError('Запрашиваемый файл не найден'): В случае отсутствия
        проверяемого файла.
      PEfileScriptsError('Запрашиваемый файл не является PE-файлом'): В случае,
        когда проверяемый файл не является PE-файлом.
      PEfileScriptsError('Таблица импорта отсутствует'): В случае отсутствия в
        PE-файле таблицы импорта.
    """
    try:
        pe = pefile.PE(file_path)
    except FileNotFoundError as err:
        raise PEfileScriptsError('Файл не найден') from err
    except pefile.PEFormatError as err:
        raise PEfileScriptsError('Файл не является PE-файлом') from err
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return len(pe.DIRECTORY_ENTRY_IMPORT)
    raise PEfileScriptsError('Таблица импорта отсутствует')

def get_imphash(file_path):
    """
    Функция вычисляет значение imphash для PE-файла.

    Аргументы:
      file_path: Путь к файлу (в виде строки).

    Возвращаемое значение:
      Значение imphash для PE-файла.

    Исключения:
      PEfileScriptsError('Запрашиваемый файл не найден'): В случае отсутствия
        проверяемого файла.
      PEfileScriptsError('Запрашиваемый файл не является PE-файлом'): В случае,
        когда проверяемый файл не является PE-файлом.
      PEfileScriptsError('Таблица импорта отсутствует'): В случае отсутствия в
        PE-файле таблицы импорта.
    """
    try:
        pe = pefile.PE(file_path)
    except FileNotFoundError as err:
        raise PEfileScriptsError('Файл не найден') from err
    except pefile.PEFormatError as err:
        raise PEfileScriptsError('Файл не является PE-файлом') from err
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return pe.get_imphash()
    raise PEfileScriptsError('Таблица импорта отсутствует')

def get_import_info(file_path):
    """
    Функция возвращает информацию о таблице импорта PE-файла.

    Аргументы:
      file_path: Путь к файлу (в виде строки).

    Возвращаемое значение:
      Информация о таблицы импорта PE-файла в виде списка с элементами:
      - имя импортируемой dll-библиотеки;
      - список API-функций для каждой dll-библиотеки.

    Исключения:
      PEfileScriptsError('Запрашиваемый файл не найден'): В случае отсутствия
        проверяемого файла.
      PEfileScriptsError('Запрашиваемый файл не является PE-файлом'): В случае,
        когда проверяемый файл не является PE-файлом.
      PEfileScriptsError('Таблица импорта отсутствует'): В случае отсутствия в
        PE-файле таблицы импорта.
    """
    try:
        pe = pefile.PE(file_path)
    except FileNotFoundError as err:
        raise PEfileScriptsError('Файл не найден') from err
    except pefile.PEFormatError as err:
        raise PEfileScriptsError('Файл не является PE-файлом') from err
    import_info = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for dll_entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = (dll_entry.dll.decode('utf-8'))
            api_name = []
            for api_entry in dll_entry.imports:
                api_name.append(api_entry.name.decode('utf-8'))
            import_info.append(dict(dll = dll_name, api = api_name))
        return import_info
    raise PEfileScriptsError('Таблица импорта отсутствует')
