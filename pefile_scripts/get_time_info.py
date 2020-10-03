"""
Модуль, реализующий функции получения значения времени компиляции PE-файла.

Функции:
    get_compilations_time(): Функция возвращающее значение времени компиляции
      файла из стандартного поля заголовка PE-файла.
    get_debug_compilations_time(): Функция возвращающее значение времени
      компиляции файла из секции DIRECTORY_ENTRY_DEBUG PE-файла.
    get_delphi_compilations_time(): Функция возвращающее значение времени
      компиляции файла, скомпилированного компилятором Delphi из секции
      DIRECTORY_ENTRY_RESOURCE PE-файла.
"""

import time
import pefile
from .pefile_scripts_exception import PEfileScriptsError

def _format_time(time_stamp_dos):
    """
    Функция преобразования формата представления времени.

    Аргументы:
        time_stamp_dos: Значение времени в DOS-формате.
    """
    day = time_stamp_dos >> 16 & 0x1f
    month = time_stamp_dos >> 21 & 0x7
    year = (time_stamp_dos >>  25 & 0xff) + 1980
    second = (time_stamp_dos & 0x1f) * 2
    minute = time_stamp_dos >> 5 & 0x3f
    hour = time_stamp_dos >> 11 & 0x1f
    return day, month, year, hour, minute, second

def get_compilations_time(file_path):
    """
    Функция возвращающая время компиляции.

    Данная функция возвращает значение времени компиляции из стандартного поля
    TimeDateStamp заголовка PE-файла.

    Аргументы:
      file_path: Путь к файлу (в виде строки).

    Возвращаемое значение:
      Строка в формате '{день}-{месяц}-{год} {часы}:{минуты}:{секунды}'.

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
    return time.strftime('%d-%m-%Y %H:%M:%S',
        time.gmtime(pe.FILE_HEADER.TimeDateStamp))

def get_debug_compilations_time(file_path):
    """
    Функция возвращающая время компиляции.

    Данная функция возвращает значение времени компиляции из поля TimeDateStamp
    секции DIRECTORY_ENTRY_DEBUG PE-файла.

    Аргументы:
      file_path: Путь к файлу (в виде строки).

    Возвращаемое значение:
      Строка в формате '{день}-{месяц}-{год} {часы}:{минуты}:{секунды}'.

    Исключения:
      PEfileScriptsError('Запрашиваемый файл не найден'): В случае отсутствия
        проверяемого файла.
      PEfileScriptsError('Запрашиваемый файл не является PE-файлом'): В случае,
        когда проверяемый файл не является PE-файлом.
      PEfileScriptsError('Отсутствует секция DIRECTORY_ENTRY_DEBUG'): В случае,
        когда в проверяемом файле отсутствует секция DIRECTORY_ENTRY_DEBUG.
    """
    try:
        pe = pefile.PE(file_path)
    except FileNotFoundError as err:
        raise PEfileScriptsError('Файл не найден') from err
    except pefile.PEFormatError as err:
        raise PEfileScriptsError('Файл не является PE-файлом') from err
    if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
        return time.strftime('%d-%m-%Y %H:%M:%S',
            time.gmtime(pe.DIRECTORY_ENTRY_DEBUG[0].struct.TimeDateStamp))
    raise PEfileScriptsError('Отсутствует секция DIRECTORY_ENTRY_DEBUG')

def get_delphi_compilations_time(file_path):
    """
    Функция возвращающая время компиляции.

    Данная функция возвращает значение времени компиляции из поля TimeDateStamp
    секции DIRECTORY_ENTRY_RESOURCE PE-файла. Может применяться для определения
    даты и времени компиляции PE-файлов, скомпилированных компилятором Delphi.

    Аргументы:
      file_path: Путь к файлу (в виде строки).

    Возвращаемое значение:
      Строка в формате '{день}-{месяц}-{год} {часы}:{минуты}:{секунды}'.

    Исключения:
      PEfileScriptsError('Запрашиваемый файл не найден'): В случае отсутствия
        проверяемого файла.
      PEfileScriptsError('Запрашиваемый файл не является PE-файлом'): В случае,
        когда проверяемый файл не является PE-файлом.
      PEfileScriptsError('Отсутствует секция DIRECTORY_ENTRY_RESOURCE'): В
        случае, когда в проверяемом файле отсутствует секция
        DIRECTORY_ENTRY_RESOURCE.
    """
    try:
        pe = pefile.PE(file_path)
    except FileNotFoundError as err:
        raise PEfileScriptsError('Файл не найден') from err
    except pefile.PEFormatError as err:
        raise PEfileScriptsError('Файл не является PE-файлом') from err
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        return '{}-{:02d}-{} {:02d}:{:02d}:{:02d}'.format(
            _format_time(pe.DIRECTORY_ENTRY_RESOURCE.struct.TimeDateStamp)[0],
            _format_time(pe.DIRECTORY_ENTRY_RESOURCE.struct.TimeDateStamp)[1],
            _format_time(pe.DIRECTORY_ENTRY_RESOURCE.struct.TimeDateStamp)[2],
            _format_time(pe.DIRECTORY_ENTRY_RESOURCE.struct.TimeDateStamp)[3],
            _format_time(pe.DIRECTORY_ENTRY_RESOURCE.struct.TimeDateStamp)[4],
            _format_time(pe.DIRECTORY_ENTRY_RESOURCE.struct.TimeDateStamp)[5]
        )
    raise PEfileScriptsError('Отсутствует секция DIRECTORY_ENTRY_RESOURCE')
