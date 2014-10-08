from distutils.core import setup

requires = [
    'multiprocessing',
    'python-nmap',
    'ipy',
    'netaddr',
    'netifaces'
]


setup(
    name='cocar-agente',
    version='1.0',
    packages=['cocar', 'cocar.tests'],
    url='http://github.com/lightbase/cocar-agente',
    license='CC-GPL v2.0',
    author='Lightbase Consultoria',
    author_email='info@lightbase.com.br',
    description='Agente coletor do software Cocar',
    install_requires=requires,
)
