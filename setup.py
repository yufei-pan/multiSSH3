from setuptools import setup
from multiSSH3 import version

setup(
    name='multiSSH3',
    version=version,
    description='Run commands on multiple hosts via SSH',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='Yufei Pan',
    author_email='pan@zopyr.us',
    url='https://github.com/yufei-pan/multiSSH3',
    py_modules=['multiSSH3'],
    entry_points={
        'console_scripts': [
            'mssh=multiSSH3:main',
            'mssh3=multiSSH3:main',
            'multissh=multiSSH3:main',
            'multissh3=multiSSH3:main',
            'multiSSH3=multiSSH3:main',
        ],
    },
    install_requires=[
        'argparse',
        'ipaddress',
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
        'Operating System :: Microsoft :: Windows',
    ],
    python_requires='>=3.6',
	license='GPLv3+',
)
