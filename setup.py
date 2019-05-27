from setuptools import setup

setup(
    name='dev-detect',
    version='0.1',
    author='CZ.NIC, z.s.p.o. (http://www.nic.cz/)',
    author_email='packaging@turris.cz',
    packages=['dev_detect'],
    url='https://gitlab.labs.nic.cz/turris/dev-detect',
    license='COPYING',
    description='Small utility to detect devices on local network',
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    install_requires=[
        'pyroute2',
        'pyuci',
    ],
    entry_points={
        'console_scripts': [
            'dev-detect = dev_detect.__main__:main'
        ]
    },
    zip_safe=True,
)
