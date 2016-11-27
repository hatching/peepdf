from setuptools import setup

execfile("peepdf/constants.py")

setup(
    name="peepdf",
    version=PEEPDF_VERSION,
    author=AUTHOR,
    license=LICENCE,
    url=PEEPDF_URL,
    install_requires=[
        "jsbeautifier==1.6.2",
        "colorama==0.3.7",
        "Pillow==3.2.0",
        "pythonaes==1.0",
        "lxml==3.6.0",
    ],
    entry_points={
        "console_scripts": [
            "peepdf = peepdf.main:main",
        ],
    },
    packages=["peepdf"],
)
