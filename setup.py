from setuptools import setup, find_packages

version = '0.3'

setup(
    name='tacacs_plus',
    version=version,
    description="A client for TACACS+ authentication",
    long_description=None,
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: BSD License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: PyPy',
    ],
    keywords='tacas tacacs+ tacacs_plus auth authentication pap chap',
    author='Ryan Petrello',
    author_email='ryan@ryanpetrello.com',
    url='http://github.com/ansible/tacacs_plus',
    license='BSD',
    packages=find_packages(exclude=['examples']),
    install_requires=['six'],
    tests_require=['pytest'],
    include_package_data=True,
    scripts=['bin/tacacs_plus'],
    test_suite='tacacs_plus',
    zip_safe=False
)
