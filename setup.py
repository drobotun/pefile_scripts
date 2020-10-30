from setuptools import setup, find_packages
import pefile_scripts

with open('README.rst', 'r', encoding='utf-8') as readme_file:
    readme = readme_file.read()
with open('HISTORY.rst', 'r', encoding='utf-8') as history_file:
    history = history_file.read()

setup(
    name = pefile_scripts.__name__,
    version = pefile_scripts.__version__,
    description = 'PE files analyses script',
    long_description = readme + '\n\n' + history,
    author = pefile_scripts.__author__,
    author_email = pefile_scripts.__author_email__,
    url='https://github.com/drobotun/pefile_scripts',
    zip_safe=False,
    license = pefile_scripts.__license__,
    keywords='PE files, analyses, import table, export table',
    project_urls={
        'Documentation': 'https://pefile_scripts.readthedocs.io/',
        'Source': 'https://github.com/drobotun/pefile_scripts'
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.0',
        'Programming Language :: Python :: 3.8',
    ],
    test_suite="tests",
    packages=find_packages(),
    install_requires=['pefile >= 2019.4.18']
    )
