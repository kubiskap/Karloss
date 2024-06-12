from setuptools import setup, find_packages

setup(
    name='Karloss',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'asn1tools',
        'folium',
        'pyshark',
        'jsonpath_ng',
        'branca'
    ],
)
