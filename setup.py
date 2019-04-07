from setuptools import setup

setup(
    name='dev-detect',
    version='0.1',
    url='https://gitlab.labs.nic.cz/turris/devdetect',
    author='CZ.NIC, z.s.p.o. (http://www.nic.cz/)',
    author_email='packaging@turris.cz',
    description='A utility to detect new devices on local network',
    zip_safe=True,
    packages=['dev_detect'],
    install_requires=[
        'pyroute2',
    ],
    entry_points={
        'console_scripts': [
            'dev-detect = dev_detect.__main__:main'
        ]
    },
)
