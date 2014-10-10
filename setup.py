from setuptools import setup, find_packages

requires = [
    'multiprocessing',
    'python-nmap',
    'ipy',
    'netaddr',
    'netifaces',
    'lxml',
    'sqlalchemy',
    'PasteScript',
    'iptools'
]


setup(
    name='cocar-agente',
    version='1.0',
    packages=find_packages(),
    include_package_data=True,
    url='http://github.com/lightbase/cocar-agente',
    license='CC-GPL v2.0',
    author='Lightbase Consultoria',
    author_email='info@lightbase.com.br',
    description='Agente coletor do software Cocar',
    test_suite='cocar',
    install_requires=requires,
    entry_points="""\
        [paste.paster_command]
            scan = cocar.commands:ScanCommands
    """,

)