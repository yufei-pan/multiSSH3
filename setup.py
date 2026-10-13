import setuptools
from setuptools import setup
from multiSSH3 import version

classifiers = [
    'Programming Language :: Python :: 3',
    'Operating System :: POSIX :: Linux',
    'Operating System :: MacOS',
    'Operating System :: Microsoft :: Windows',
]
# setuptools 77+ (PEP 639) takes an SPDX license expression and warns about license classifiers (an error next to an
# expression); older ones, all there is on Python 3.6, know only the free-text license and the classifier
if int(setuptools.__version__.split('.')[0]) >= 77:
    license_metadata = {'license_expression': 'GPL-3.0-or-later'}
else:
    license_metadata = {'license': 'GPL-3.0-or-later'}
    classifiers.append('License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)')

setup(
    name='multiSSH3',
    version=version,
    description='Run commands on multiple hosts via SSH',
    long_description=open('README.md', encoding='utf-8').read(),
    long_description_content_type='text/markdown',
    author='Yufei Pan',
    author_email='pan@zopyr.us',
    url='https://github.com/yufei-pan/multiSSH3',
    py_modules=['multiSSH3', 'mssh_complete'],
    entry_points={
        'console_scripts': [
            'mssh=multiSSH3:main',
            'mssh3=multiSSH3:main',
            'multissh=multiSSH3:main',
            'multissh3=multiSSH3:main',
            'multiSSH3=multiSSH3:main',
            'mssh-complete=mssh_complete:main',
        ],
    },
    classifiers=classifiers,
    python_requires='>=3.6',
    **license_metadata
)
