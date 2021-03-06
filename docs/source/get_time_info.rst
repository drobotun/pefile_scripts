Модуль **get_time_info**
========================

Функция **get_compile_time**
---------------------------------

Возвращает значение времени компиляции из стандартного поля ``TimeDateStamp`` заголовка PE-файла.

.. rubric:: Аргументы:

- **file_path** - строка, содержащая путь PE-файлу.

.. rubric:: Возвращаемое значение:

Строка в формате {день}-{месяц}-{год} {часы}:{минуты}:{секунды}.

.. rubric:: Исключения:

- **PEfileScriptsError** ('Запрашиваемый файл не найден'): В случае отсутствия проверяемого PE-файла.
- **PEfileScriptsError** ('Запрашиваемый файл не является PE-файлом'): В случае, когда проверяемый файл не является PE-файлом.

Функция **get_debug_compile_time**
---------------------------------------

Возвращает значение времени компиляции из поля ``TimeDateStamp`` секции ``DIRECTORY_ENTRY_DEBUG`` PE-файла.

.. rubric:: Аргументы:

- **file_path** - строка, содержащая путь PE-файлу.

.. rubric:: Возвращаемое значение:

Строка в формате {день}-{месяц}-{год} {часы}:{минуты}:{секунды}.

.. rubric:: Исключения:

- **PEfileScriptsError** ('Запрашиваемый файл не найден'): В случае отсутствия проверяемого PE-файла.
- **PEfileScriptsError** ('Запрашиваемый файл не является PE-файлом'): В случае, когда проверяемый файл не является PE-файлом.
- **PEfileScriptsError** ('Отсутствует секция DIRECTORY_ENTRY_DEBUG'): В случае, когда в проверяемом файле отсутствует секция ``DIRECTORY_ENTRY_DEBUG``.

Функция **get_delphi_compile_time**
----------------------------------------

Возвращает значение времени компиляции из поля ``TimeDateStamp`` секции ``DIRECTORY_ENTRY_RESOURCE`` PE-файла. Может применяться для определения даты и времени компиляции PE-файлов, скомпилированных компилятором Delphi (для PE-файлов, скомпилированных компилятором Delphi, стандартное поле ``TimeDateStamp`` всегда содержит 0 часов 0 минут 19 июня 1992 года).

.. rubric:: Аргументы:

- **file_path** - строка, содержащая путь PE-файлу.

.. rubric:: Возвращаемое значение:

Строка в формате {день}-{месяц}-{год} {часы}:{минуты}:{секунды}.

.. rubric:: Исключения:

- **PEfileScriptsError** ('Запрашиваемый файл не найден'): В случае отсутствия проверяемого PE-файла.
- **PEfileScriptsError** ('Запрашиваемый файл не является PE-файлом'): В случае, когда проверяемый файл не является PE-файлом.
- **PEfileScriptsError** ('Отсутствует секция DIRECTORY_ENTRY_RESOURCE'): В случае, когда в проверяемом файле отсутствует секция ``DIRECTORY_ENTRY_DEBUG``.
