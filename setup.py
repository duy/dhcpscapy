from setuptools import setup,  find_packages
setup(
    name='dhcpscapy',
    version='0.1',
    description='Simple DCHP client and server implemented with scapy.',
    author='duy',
    author_email='duy at rhizoma dot tk',
    url='https://github.com/duy/dhcpscapy',
    install_requires=[
        'scapy==2.2.0', 
        'netaddr==0.7.10', 
        'ipaddr==2.1.11', 
    ],
    setup_requires=[],
    entry_points = {
        'console_scripts' : ['dchpclientscapy = scripts.dhcpclientscapy:main', 
            'dchpserverscapy = scripts.dhcpserverscapy:main']
    },

    keywords = 'python scapy dhcp',
    license = 'GPLv3+',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Operating System :: OS Independent',
        'Programming Language :: Python'
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
