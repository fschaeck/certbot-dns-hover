
from setuptools import __version__ as setuptools_version
from setuptools import find_packages
from setuptools import setup

version = '1.2.0'

install_requires = [
    'acme>=0.29.0',
    'certbot>=0.34.0',
    'setuptools',
    'requests',
    'mock',
    'requests-mock',
]

# read the contents of the README file
from os import path
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, "README.rst")) as f:
    long_description = f.read()

setup(
    name='certbot-dns-hover',
    version=version,
    description="Hover (www.hover.com) DNS Authenticator plugin for Certbot",
    long_description=long_description,
    long_description_content_type='text/x-rst',
    url='https://github.com/fschaeck/certbot-dns-hover',
    author="Frank Schäckermann",
    author_email='certbot.hover-fschaeckermann@snkmail.com',
    license='Apache License 2.0',
    python_requires='>=2.7, !=3.0.*, !=3.1.*, != 3.2.*, !=3.3.*',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    entry_points={
        'certbot.plugins': [
            'dns-hover = certbot_dns_hover.dns_hover:Authenticator',
        ],
    },
    test_suite='certbot_dns_hover',
)
