import re
import setuptools

version = re.search(
    '^__version__\s*=\s*\'(.*)\'',
    open('hsecscan/hsecscan.py').read(),
    re.M
    ).group(1)

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="hsecscan",
    version=version,
    author="Ricardo Iramar dos Santos",
    author_email="ricardo.iramar@gmail.com",
    description="A security scanner for HTTP response headers.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/riramar/hsecscan/blob/master/README.md",
    entry_points={
        "console_scripts": ['hsecscan = hsecscan.hsecscan:main']
        },
    packages=setuptools.find_packages(),
    package_data={'hsecscan': ['hsecscan.db']},
    classifiers=(
        "Programming Language :: Python :: 2.7",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: OS Independent",
    ),
)
