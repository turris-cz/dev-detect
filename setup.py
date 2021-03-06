from setuptools import setup

setup(
    name='dev-detect',
    version='0.3.1',
    author='CZ.NIC, z.s.p.o. (http://www.nic.cz/)',
    author_email='packaging@turris.cz',
    packages=['dev_detect'],
    url='https://gitlab.nic.cz/turris/dev-detect',
    license='GPL-3.0-only',
    description='Small utility to detect devices on local network',
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    install_requires=[
        'pyroute2',
        'pyuci @ git+https://gitlab.nic.cz/turris/pyuci.git',
    ],
    entry_points={
        'console_scripts': [
            'dev-detect-daemon = dev_detect.__main__:main',
            'dev-detect = dev_detect.cli:main'
        ]
    },
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3 :: Only',
    ],
    python_requires='~=3.6',
    zip_safe=True,
)
