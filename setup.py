from setuptools import setup, find_packages

setup(
    name='hsecscan',
    version='0.2',
    author='Ricardo Iramar Dos Santos',
    license='GPLv2',
    packages=find_packages(),
    package_data={
        'hsecscan': ['hsecscan.db'],
    },
    entry_points={
        'console_scripts': [
            'hsecscan=hsecscan:main',
        ]
    },
)
