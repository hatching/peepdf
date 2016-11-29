import sys
import os
from setuptools import setup

is_winnt = os.name == "nt"
is_linux = os.name == "posix" and sys.platform.startswith("linux")
is_mac   = os.name == "mac"
is_osx   = os.name == "posix" and sys.platform == "darwin"

if is_winnt:
    lxml_require = "lxml==3.6.0"
else:
    lxml_require = "lxml==3.6.4"

setup(
    name="peepdf",
    version="0.3.3",
    author="Jose Miguel Esparza",
    license="GNU GPLv3",
    url="http://eternal-todo.com",
    install_requires=[
        "jsbeautifier==1.6.4",
        "colorama==0.3.7",
        "Pillow==3.2.0",
        "pythonaes==1.0",
        lxml_require,
    ],
    entry_points={
        "console_scripts": [
            "peepdf = peepdf.main:main",
        ],
    },
    packages=["peepdf"],
)
