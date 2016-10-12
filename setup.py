from setuptools import setup

setup(
    name='slashlock',
    version='0.1.2',
    description='Slashlock - A Simple File and Folder Encryptor',
    url='https://github.com/wookalar/slashlock/blob/master/slashlock.py',
    author='Wookalar Software',
    author_email='doc.tart@wookalar.io',
    license='AGPLv3',
    entry_points={'gui_scripts': [
        'slashlock = slashlock:main',
    ]},
    install_requires=[
        'argon2-cffi>=16.2.0',
        'PyNaCl>=1.0.1',
    ],
    install_package_data=False,
    py_modules=['slashlock'],
)
