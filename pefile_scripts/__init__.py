"""Пакет, реализующий функции получения информации из заголовка PE-файла.

Пакет включает модули:
    - get_time_info: Реализует функции получения значения времени компиляции
      PE-файла.
    - get_section_info: Реализует функции получения информации о секциях
      PE-файла.
    - get_import_info: Реализует функции получения информации о секции импорта
      PE-файла.
    - get_export_info: Реализует функции получения информации о секции экспорта
      PE-файла.

Исходный код:
    https://github.com/drobotun/pefile_scripts
Документация:
    https://pefile-scripts.readthedocs.io/
"""

__title__ = 'pefile_scripts'
__version__ = '0.0.1'
__author__ = 'Evgeny Drobotun'
__author_email__ = 'drobotun@xakep.ru'
__license__ = 'MIT'
__copyright__ = 'Copyright (C) 2020 Evgeny Drobotun'

from importlib.util import find_spec
from sys import version_info
from sys import exit as sys_exit

if version_info.major < 3:
    print('Используйте python версии 3.0 и выше')
    sys_exit()

if find_spec('pefile') is None:
    print('Необходимо загрузить пакет pefile')
    sys_exit()

from .get_time_info import (
    get_compile_time,
    get_debug_compile_time,
    get_delphi_compile_time
)

from .get_section_info import(
    get_section_num,
    get_section_info
)

from .get_import_info import(
    get_dll_num,
    get_imphash,
    get_import_info
)

from .get_export_info import(
    get_export_api_num,
    get_export_dll_name,
    get_export_info
)

from .pefile_scripts_exception import PEfileScriptsError
