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
    'iptools',
    'requests',
    'mock',
    'alembic'
]


setup(
    name='cocar-agente',
    version='1.1.0b1',
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
            printer = cocar.commands:PrinterCommands
            network_device = cocar.commands:NetworkDeviceCommands
    """,

)
