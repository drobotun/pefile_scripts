Python-скрипты для анализа PE-файлов
====================================

.. image:: https://api.codacy.com/project/badge/Grade/88b2f636a6254379ade0146485629977
   :alt: Codacy Badge
   :target: https://app.codacy.com/gh/drobotun/pefile_scripts?utm_source=github.com&utm_medium=referral&utm_content=drobotun/pefile_scripts&utm_campaign=Badge_Grade_Settings

.. image:: https://readthedocs.org/projects/pefile-scripts/badge/?version=latest
    :target: https://pefile-scripts.readthedocs.io

.. image:: https://travis-ci.com/drobotun/pefile_scripts.svg?branch=master
    :target: https://travis-ci.com/drobotun/pefile_scripts

.. image:: https://codecov.io/gh/drobotun/pefile_scripts/branch/master/graph/badge.svg?token=zMRIxawPrr
    :target: https://codecov.io/gh/drobotun/pefile_scripts

.. image:: https://app.codacy.com/project/badge/Grade/165704639e2644289941451cdb930d00
    :target: https://www.codacy.com/gh/drobotun/pefile_scripts/dashboard?

Пакет включает в себя четыре модуля:

- **get_time_info** - содержит функции для получения времени компиляции PE-файла.
- **get_section_info** - содержит функции для получении информации о секциях PE-файла. Позволяет получать информацию о количестве секций в PE-файле, их названиях, значения поля **Characteristics**, значения MD5-хэша и энтропии для каждой секции.
- **get_import_info** - содержит функции для получения информации о таблице импорта PE-файла. Позволяет получать информацию о количестве импортируемых dll-библиотек, значение imphash, а также список импортируемых api-функций для каждой dll-библиотеки.
- **get_export_info** - содержит функции для получения информации о таблице экспорта PE-файла. Позволяет получать информацию о количестве экспортируемых функций, имена экспортируемых функций (при их наличии), а также значения номеров (ординалов) и значения RVA-адресов для всех экспортируемых функций.

Инсталляция пакета
------------------

.. code-block:: bash

    pip install pefile_scripts

Примеры использования
---------------------

Командная строка
++++++++++++++++

.. code:: bash

    python -m pefile_scripts [-ct] [-cdt] [-crt] [-sn] [-si]
                             [-dn] [-ih] [-ii] [-ean] [-edn]
                             [-ei] [-h] <ФАЙЛ>
							  
- **ФАЙЛ** - путь к анализируемому PE-файлу
- **-ct, --compilation-time** - время компиляции PE-файла из стандартного поля ``TimeDateStamp``
- **-cdt, --debug-compilation-time** - время компиляции PE-файла из секции ``DIRECTORY_ENTRY_DEBUG``
- **-crt, --delphi-compilation-time** - Время компиляции PE-файла из секции ``RESOURCE_ENTRY_DEBUG``
- **-sn, --section-num** - Число секций в PE-файле
- **-si, --section-info** - Информация о секциях PE-файла
- **-dn, --dll-num** - Число импортируемых dll-библиотек
- **-ih, --imphash** - Значение imphash таблицы импорта PE-файла
- **-ii, --import-info** - Информация о таблице импорта PE-файла
- **-ean, --export-api-num** - Число экспортируемых функций
- **-edn, --export-dll-name** - Название библиотеки
- **-ei, --export-info** - Информация о таблице экспорта PE-файла
- **-h, --help** - Выводит справку по программе

Python программы
++++++++++++++++

Модуль get_time_info
~~~~~~~~~~~~~~~~~~~~

.. rubric:: get_compilations_time()

.. code-block:: python

    import pefile_scripts

    try:
        print('Время компиляции файла:', pefile_scripts.get_compilations_time('c:/test_file.exe'))
    except pefile_scripts.PEfileScriptsError as err:
        print(err)

.. rubric:: get_debug_compilations_time()

.. code-block:: python

    import pefile_scripts

    try:
        print('Время компиляции файла:', pefile_scripts.get_debug_compilations_time('c:/test_file.exe'))
    except pefile_scripts.PEfileScriptsError as err:
        print(err)

.. rubric:: get_delphi_compilations_time()

.. code-block:: python

    import pefile_scripts

    try:
        print('Время компиляции файла:', pefile_scripts.get_delphi_compilations_time('c:/test_file.exe'))
    except pefile_scripts.PEfileScriptsError as err:
        print(err)

Модуль get_section_info
~~~~~~~~~~~~~~~~~~~~~~~

.. rubric:: get_section_num()

.. code:: python

    import pefile_scripts

    try:
        print('Число секций в файле:', pefile_scripts.get_section_num('c:/test_file.exe'))
    except pefile_scripts.PEfileScriptsError as err:
        print(err)

.. rubric:: get_section_info()

.. code:: python

    import pefile_scripts

    try:
        for section_entry in pefile_scripts.get_section_info('e:/c:/test_file.exe'):
            print(section_entry['name'])
            print('\tCharacteristics: ', section_entry['characteristics'])
            print('\tMD5-хэш секции: ', section_entry['MD5hash'])
            print('\tЭнтропия секции: ', section_entry['entropy'])
    except pefile_scripts.PEfileScriptsError as err:
        print(err)

Модуль get_import_info
~~~~~~~~~~~~~~~~~~~~~~

.. rubric:: get_import_num()

.. code:: python

    import pefile_scripts

    try:
        print('Число dll-библиотек в файле:', pefile_scripts.get_dll_num('c:/test_file.exe'))
    except pefile_scripts.PEfileScriptsError as err:
        print(err)

.. rubric:: get_imphash()

.. code:: python

    import pefile_scripts

    try:
        print('Значение imphash:', pefile_scripts.get_imphash('c:/test_file.exe'))
    except pefile_scripts.PEfileScriptsError as err:
        print(err)

.. rubric:: get_import_num()

.. code:: python

    import pefile_scripts
	
    try:
        for import_entry in pefile_scripts.get_import_info('e:/hashcalc.exe'):
            print('Из', import_entry['dll'], 'импортируются:')
            for api_entry in import_entry['api']:
                print('\t', api_entry)
    except pefile_scripts.PEfileScriptsError as err:
        print(err)

Модуль get_export_info
~~~~~~~~~~~~~~~~~~~~~~

.. rubric:: get_export_api_num()

.. code:: python

    import pefile_scripts

    try:
        print('Число экспортируемых функций:', pefile_scripts.get_export_api_num('c:/test_file.exe'))
    except pefile_scripts.PEfileScriptsError as err:
        print(err)

.. rubric:: get_export_dll_name()

.. code:: python

    import pefile_scripts

    try:
        print('Имя dll-библиотеки:', pefile_scripts.get_export_dll_name('c:/test_file.exe'))
    except pefile_scripts.PEfileScriptsError as err:
        print(err)

.. rubric:: get_export_info()

.. code:: python

    import pefile_scripts

    try:
        for export_entry in pefile_scripts.get_export_info('c:/test_file.dll'):
            print('Имя экспортируемой функции:', export_entry['api'])
            print('\t Номер (ординал):', export_entry['ordinal'])
            print('\t RVA-адрес:', export_entry['rva'])
    except pefile_scripts.PEfileScriptsError as err:
        print(err)

Сведения о лицензии
-------------------

MIT Copyright (c) 2020 Евгений Дроботун

Исходный код
------------

https://github.com/drobotun/pefile_scripts

Документация
------------

https://pefile-scripts.readthedocs.io
