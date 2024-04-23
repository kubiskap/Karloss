from setuptools import setup

with open("README.ms", 'r') as f:
    long_description = f.read()

setup(
   name='Karloss',
   version='0.2',
   description='Simple C-ITS message verification based on ASN definitions.',
   license="GPL-3.0",
   long_description=long_description,
   author='Petr Miloslav Kubiska',
   author_email='kubispe3@fd.cvut.cz',
   url="https://github.com/kubiskap/Karloss",
   packages=['Karloss'],  #same as name
   install_requires=['pyshark', 'asn1tools', 'jsonpath_ng', 'tk', 'folium']  # external packages as dependencies
)