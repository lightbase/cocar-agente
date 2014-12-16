#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'
import logging
import os
import os.path
import lxml.etree
import time
import pickle
import requests
from paste.script import command
from .. import Cocar
from ..model import Base
from ..model.network import Network
from ..model.printer import Printer, PrinterCounter
from ..model.host import Host
from ..model.computer import Computer
from ..csv_utils import NetworkCSV
from ..session import NmapSession, SnmpSession, ArpSession
from multiprocessing import Process, Queue
from ..xml_utils import NmapXML
from sqlalchemy.exc import IntegrityError
from sqlalchemy import and_

log = logging.getLogger()


class ScanCommands(command.Command):
    """
    Comandos  para realizar o scan da rede
    Usage::
        paster scan create_db -c <path to config file>
            - Cria banco de dados
        paster scan drop_db -c <path to config file>
            - Remove banco de dados
        paster scan networks -c <path to config file>
            - Faz a busca das redes

    Os comandos devem ser executados a partir da raiz do modulo Cocar
    """
    max_args = 1
    min_args = 1
    summary = __doc__.split('\n')[0]
    usage = __doc__
    group_name = "Scan Commands"

    parser = command.Command.standard_parser(verbose=True)

    parser.add_option('-f', '--full',
                      action='store',
                      dest='full',
                      help='Full scan or regular scan'
    )

    parser.add_option('-i', '--ip',
                      action='store',
                      dest='hosts',
                      help='Hosts list to scan'
    )

    parser.add_option('-q', '--query',
                      action='store',
                      dest='query',
                      help='SNMP query to execute'
    )

    parser.add_option('-t', '--timeout',
                      action='store',
                      dest='timeout',
                      help='Timeout da consulta SNMP'
    )

    parser.add_option('-n', '--networks',
                      action='store',
                      dest='networks',
                      help='Arquivo individual de rede para ser carregado'
    )

    parser.add_option('-a', '--iface',
                      action='store',
                      dest='iface',
                      help='Interface de rede para utilizar no Arping'
    )

    def __init__(self, name):
        """
        Constructor method

        """
        super(ScanCommands, self).__init__(name)
        self.cocar = Cocar(environment='production')
        self.networks_dir = self.cocar.cocar_data_dir + "/networks"
        self.networks_csv = self.cocar.config.get('cocar', 'networks_csv')
        if not os.path.isdir(self.networks_dir):
            os.mkdir(self.networks_dir)

    def command(self):
        """
        Parse command line arguments and call appropriate method.
        """

        if not self.args or self.args[0] in ['--help', '-h', 'help']:
            print(ScanCommands.__doc__)
            return

        cmd = self.args[0]

        if cmd == 'create_db':
            self.create_db()
            return
        if cmd == 'drop_db':
            self.drop_db()
            return
        if cmd == 'load_networks':
            self.load_networks()
            return
        if cmd == 'scan_networks':
            self.scan_networks()
            return
        if cmd == 'load_network_files':
            self.load_network_files()
            return
        if cmd == 'get_printers':
            self.get_printers()
            return
        if cmd == 'continous_scan':
            self.continuous_scan()
            return
        if cmd == 'printer_scan':
            self.printer_scan()
            return
        if cmd == 'export_printers':
            self.export_printers()
            return
        if cmd == 'get_printer_attribute':
            self.get_printer_attribute()
            return
        if cmd == 'load_file':
            self.load_file()
            return
        if cmd == 'import_printers':
            self.import_printers()
            return
        if cmd == 'get_mac':
            self.get_mac()
            return
        if cmd == 'scan_mac':
            self.scan_mac()
            return
        if cmd == 'scan_mac_all':
            self.scan_mac_all()
            return
        else:
            log.error('Command "%s" not recognized' % (cmd,))

    def create_db(self):
        """
        Create database
        """
        Base.metadata.create_all(self.cocar.engine)

    def drop_db(self):
        """
        Drop database
        """
        Base.metadata.drop_all(self.cocar.engine)

    def load_networks(self):
        """
        Load networks from CSV file
        """
        #networks_csv = NetworkCSV(csv_file=self.networks_csv)
        # First download Networks from Cocar
        url = self.cocar.config.get('cocar', 'server_url') + '/api/networks'
        response = requests.get(
            url
        )
        networks_json = response.json()
        session = self.cocar.Session
        for elm in networks_json['networks']:
            network = Network(
                network_ip=elm['ip_network'],
                netmask=elm['netmask'],
                name=elm['name']
            )
            results = session.query(Network).filter(Network.ip_network == network.ip_network).first()
            if results is None:
                log.info("Adicionando a rede: %s", network.ip_network)
                session.add(network)
            else:
                log.info("Rede já cadastrada: %s. Atualizando informações...", network.ip_network)
                session.execute(
                    Network.__table__.update().values(
                        netmask=elm['netmask'],
                        name=elm['name'],
                        ip_network=network.ip_network
                    ).where(
                        Network.__table__.c.ip_network == network.ip_network
                    )
                )

        session.flush()
        session.close()

    def scan_networks(self):
        """
        Scan all networks
        """
        processes = int(self.cocar.config.get('cocar', 'processes'))
        # Create queues
        task_queue = Queue()
        done_queue = Queue()

        session = self.cocar.Session
        results = session.query(Network).all()
        for network in results:
            network.network_ip = network.ip_network
            network.network_file = self.networks_dir + "/" + str(network.network_ip.cidr).replace("/", "-") + ".xml"
            if self.options.full is None:
                nmap_session = NmapSession(
                    network.network_ip.cidr,
                    outfile=network.network_file,
                    full=False
                )
            else:
                nmap_session = NmapSession(
                    network.network_ip.cidr,
                    outfile=network.network_file,
                    full=True
                )

            # Store network file name on Network object
            network = session.merge(network)
            session.flush()

            # Add search on network
            task_queue.put(nmap_session)

        #Start worker processes
        for i in range(processes):
            Process(target=worker, args=(task_queue, done_queue)).start()

        # Get and print results
        print 'Unordered results:'
        for i in range(len(results)):
            print '\t', done_queue.get()

        # Tell child processes to stop
        for i in range(processes):
            task_queue.put('STOP')

    def load_network_files(self):
        """
        Load printers from networks files
        :return:
        """
        #onlyfiles = [ f for f in os.listdir(self.networks_dir) if os.path.isfile(os.path.join(self.networks_dir, f)) ]
        session = self.cocar.Session

        # Look for network files in DB
        results = session.query(Network.__table__).all()
        onlyfiles = list()
        for network in results:
            onlyfiles.append(network)

        self.options.networks = onlyfiles
        return self.load_file()

    def get_printers(self):
        """
        Read printers SNMP Information
        :return:
        """
        processes = int(self.cocar.config.get('cocar', 'processes'))
        # Create queues
        task_queue = Queue()
        done_queue = Queue()

        session = self.cocar.Session
        if self.options.hosts is None:
            results = session.query(Printer).all()
        else:
            results = session.query(Printer).filter(
                Printer.network_ip.in_(self.options.hosts)
            ).all()

        for printer in results:
            log.info("Coletando informacoes da impressora %s", printer.network_ip)
            #printer.network_ip = printer.ip_network
            snmp_session = SnmpSession(
                DestHost=printer.network_ip,
                Timeout=self.options.timeout
            )
            if snmp_session is None:
                log.error("Erro na coleta SNMP da impressora %s", printer.network_ip)
                continue
            else:
                task_queue.put(snmp_session)

        #Start worker processes
        for i in range(processes):
            Process(target=worker_printer, args=(task_queue, done_queue)).start()

        # Get and print results
        log.debug('Unordered results:')
        for i in range(len(results)):
            printer_dict = done_queue.get()
            log.debug(printer_dict)
            if printer_dict['counter'] is None:
                log.error("Nao foi possivel ler o contador da impressora %s", printer_dict['network_ip'])
                continue

            try:
                log.debug("Gravando contador = %s para a impressora = %s serial = %s", printer_dict['counter'], printer_dict['network_ip'], printer_dict['serial'])
                printer = PrinterCounter(
                    ip_address=printer_dict['network_ip'],
                    model=printer_dict['model'],
                    serial=printer_dict['serial'],
                    description=printer_dict['description'],
                    counter=printer_dict['counter'],
                    counter_time=time.time()
                )
                printer.update_counter(session)
            except AttributeError, e:
                log.error("Erro na inserção do contador para a impressora %s\n%s", printer_dict['network_ip'], e.message)
                continue

        # Tell child processes to stop
        for i in range(processes):
            task_queue.put('STOP')

    def continuous_scan(self):
        """
        Fica varrendo a rede até parar por execução forçada
        """
        print("*** Aperente CTRL+C para encerrar a execução ***")

        while True:
            log.info("Carregando informações das subredes...")
            self.load_networks()

            log.info("Iniciando scan de redes...")
            self.scan_networks()

            log.info("Scan de redes finalizado. Iniciando procedimento de "
                     "identificação de ativos de rede, computadores e impressoras")
            self.load_network_files()
            log.info("SCAN DE REDE COMPLETO FINALIZADO!!!")

    def printer_scan(self):
        """
        Fica varrendo a rede e tenta encontrar as impressoras a cada 10min
        """
        print("*** Aperente CTRL+C para encerrar a execução ***")

        while True:
            self.get_printers()
            log.info("SCAN DE IMPRESSORAS FINALIZADO!!! Iniciando export de coletores")

            self.export_printers()
            log.info("EXPORT DE IMPRESSORAS FINALIZADO!!! Reiniciando as coletas")
            #time.sleep(600)

    def scan_mac_all(self):
        """
        Fica varrendo a rede tentando arrumar os MAC's
        """
        print("*** Aperente CTRL+C para encerrar a execução ***")

        while True:
            self.scan_mac()
            log.info("SCAN DE MAC FINALIZADO!!!")

    def export_printers(self):
        """
        Exporta todos os contadores para o Cocar
        """
        session = self.cocar.Session
        results = session.query(Printer).join(
            PrinterCounter.__table__,
            PrinterCounter.network_ip == Printer.network_ip
        ).all()
        for printer in results:
            log.info("Exportando impressora %s", printer.network_ip)
            printer.export_printer(server_url=self.cocar.config.get('cocar', 'server_url'), session=session)

        session.close()
        log.info("EXPORT DAS IMPRESSORAS FINALIZADO!!! %s IMPRESSORAS EXPORTADAS!!!", len(results))

    def get_printer_attribute(self):
        """
        Retorna e grava um atributo n   o valor da impressora
        """
        session = self.cocar.Session
        if self.options.hosts is None:
            results = session.query(Printer).all()
        elif type(self.options.hosts) == list:
            results = session.query(Printer).filter(
                Printer.network_ip.in_(self.options.hosts)
            ).all()
        else:
            results = session.query(Printer).filter(
                Printer.network_ip == self.options.hosts
            ).all()

        if len(results) == 0:
            log.error("Impressoras não encontradas")
            log.error(self.options.hosts)

        for printer in results:
            log.info("Coletando informacoes da impressora %s", printer.network_ip)
            #printer.network_ip = printer.ip_network
            snmp_session = SnmpSession(
                DestHost=printer.network_ip,
                Timeout=self.options.timeout
            )
            if snmp_session is None:
                log.error("Erro na coleta SNMP da impressora %s", printer.network_ip)
                continue
            else:
                log.info("Iniciando coleta da impressora %s", printer.network_ip)
                printer_dict = dict()
                if type(self.options.query != list):
                    test = self.options.query
                    self.options.query = list()
                    self.options.query.append(test)

                for i in range(len(self.options.query)):
                    if self.options.query[i] == 'description':
                        status = snmp_session.printer_full()
                        printer_dict['description'] = status
                    elif self.options.query[i] == 'serial':
                        status = snmp_session.printer_serial()
                        printer_dict['serial'] = status
                    elif self.options.query[i] == 'model':
                        status = snmp_session.printer_model()
                        printer_dict['model'] = status
                    elif self.options.query[i] == 'counter':
                        status = snmp_session.printer_counter()
                        printer_dict['counter'] = status
                    elif self.options.query[i] == 'status':
                        status = snmp_session.printer_status()
                        printer_dict['status'] = status
                log.debug(printer_dict)
                try:
                    log.debug("Atualizando informacoes da impressora %s", printer.network_ip)
                    log.debug(printer_dict)

                    if printer_dict.get('counter') is not None:

                        printer_counter = PrinterCounter(
                            ip_address=printer.network_ip,
                            counter=printer_dict['counter'],
                            counter_time=time.time()
                        )

                        if printer_dict.get('model') is not None:
                            printer_counter.model = printer_dict['model']
                            printer.model = printer_dict['model']

                        if printer_dict.get('serial') is not None:
                            printer_counter.serial = printer_dict['serial']
                            printer.serial = printer_dict['serial']

                        if printer_dict.get('description') is not None:
                            printer_counter.description = printer_dict['description']
                            printer.description = printer_dict['description']

                        # Para esse caso atualiza o contador
                        printer_counter.update_counter(session)
                    else:
                        # Nesse caso só atualizo a impressora
                        if printer_dict.get('model') is not None:
                            printer.model = printer_dict['model']

                        if printer_dict.get('serial') is not None:
                            printer.serial = printer_dict['serial']

                        if printer_dict.get('description') is not None:
                            printer.description = printer_dict['description']

                    session.execute(
                        Printer.__table__.update().values(
                            model=printer.model,
                            description=printer.description,
                            serial=printer.serial
                        ).where(
                            Printer.__table__.c.network_ip == printer.network_ip
                        )
                    )
                    session.flush()

                except IntegrityError, e:
                    log.error("Erro na atualizacao das informacoes para a impressora %s\n%s", printer.network_ip, e.message)
                    continue

        session.close()

    def load_file(self):
        """
        Load printers from networks files
        :return:
        """
        session = self.cocar.Session
        onlyfiles = list()
        if type(self.options.networks) == list:
            for elm in self.options.networks:
                onlyfiles.append(elm)
        else:
            network = session.query(Network.__table__).filter(
                Network.__table__.c.ip_network == self.options.networks
            ).first()
            if network is not None:
                onlyfiles.append(network)
            else:
                log.error("Rede não encontrada: %s", self.options.networks)
                return

        for i in range(len(onlyfiles)):
            network = onlyfiles[i]
            network_file = network.network_file
            log.info("Processando arquivo de rede %s", network_file)
            nmap_xml = NmapXML(network_file)
            try:
                host_dict = nmap_xml.parse_xml()
            except AttributeError as e:
                log.error("Erro de Atributo!!! "
                          "Erro realizando parsing do arquivo %s\n%s", network_file, e.message)
                continue
            except lxml.etree.XMLSyntaxError as e:
                log.error("Erro de parsing!!!! "
                          "Erro realizando parsing do arquivo %s\n%s", network_file, e.message)
                continue
            except IOError as e:
                log.error("Arquivo não encontrado!!! "
                          "Arquivo %s não encontrado\n%s", network_file, e.message)

            if not host_dict:
                log.error("File %s not found", network_file)
                continue

            session = self.cocar.Session
            for hostname in nmap_xml.hosts.keys():
                host = nmap_xml.identify_host(hostname, timeout=self.options.timeout)

                # Adiciona host na Rede
                host.ip_network = network.ip_network

                # Antes de tudo verifica se ele já está na tabela de contadores
                counter = session.query(
                    PrinterCounter.__table__
                ).outerjoin(
                    Printer.__table__,
                    PrinterCounter.network_ip == Printer.network_ip
                ).filter(
                    and_(
                        PrinterCounter.network_ip == hostname,
                        Printer.network_ip.is_(None)
                    )
                ).first()

                if counter is not None:
                    # Agora insere a impressora
                    log.info("Inserindo impressora com o IP %s", hostname)
                    Host.__table__.update().values(
                        ip_network=network.ip_network
                    ).where(
                        Host.__table__.c.network_ip == host.network_ip
                    )

                    session.execute(
                        Printer.__table__.insert().values(
                            network_ip=host.network_ip
                        )
                    )
                    session.flush()
                    continue

                if isinstance(host, Printer):
                    # Vê se a impressora já está na base
                    results = session.query(Printer).filter(Printer.network_ip == hostname).first()
                    if results is None:
                        log.info("Inserindo impressora com o IP %s", hostname)
                        try:
                            session.add(host)
                            session.flush()
                        except IntegrityError, e:
                            log.error("Erro adicionando impressora com o IP %s. IP Repetido\n%s", hostname, e.message)
                            # Pode haver um host cadastrado que não havia sido identificado como impressora
                            teste = session.query(Host).filter(Host.network_ip == hostname).first()
                            if teste is not None:
                                # Adiciona a impressora
                                session.execute(
                                    Printer.__table__.insert().values(
                                        network_ip=hostname
                                    )
                                )
                                log.info("Impressora %s adicionada novamente com sucesso", hostname)

                                # Agora atualiza informações do host
                                if host.mac_address is not None:
                                    session.execute(
                                        Host.__table__.update().values(
                                            mac_address=host.mac_address,
                                            name=host.name,
                                            ports=host.ports,
                                            ip_network=host.ip_network
                                        ).where(
                                            Host.network_ip == hostname
                                        )
                                    )
                                    session.flush()
                                    log.info("Informações do host %s atualizadas com sucesso", hostname)
                            else:
                                log.error("ERRO!!! Host não encontrado com o IP!!! %s", hostname)
                    else:
                        log.info("Impressora com o IP %s já cadastrada", hostname)
                elif isinstance(host, Computer):
                    # Vê se o host já está na base
                    results = session.query(Computer).filter(Computer.network_ip == hostname).first()
                    if results is None:
                        log.info("Inserindo computador com o IP %s", hostname)
                        try:
                            session.add(host)
                            session.flush()
                        except IntegrityError, e:
                            log.error("Erro adicionando computador com o IP %s. IP Repetido\n%s", hostname, e.message)
                            # Agora atualiza informações do host
                            if host.mac_address is not None:
                                session.execute(
                                    Host.__table__.update().values(
                                        mac_address=host.mac_address,
                                        name=host.name,
                                        ports=host.ports,
                                        ip_network=host.ip_network
                                    ).where(
                                        Host.network_ip == hostname
                                    )
                                )
                                session.flush()
                                log.info("Informações do host %s atualizadas com sucesso", hostname)
                    else:
                        log.info("Computador com o IP %s já cadastrado", hostname)
                        # Agora atualiza informações do host
                        if host.mac_address is not None:
                            session.execute(
                                Host.__table__.update().values(
                                    mac_address=host.mac_address,
                                    name=host.name,
                                    ports=host.ports,
                                    ip_network=host.ip_network
                                ).where(
                                    Host.network_ip == hostname
                                )
                            )
                            session.flush()
                            log.info("Informações do host %s atualizadas com sucesso", hostname)
                else:
                    # Insere host genérico
                    results = session.query(Host).filter(Host.network_ip == hostname).first()
                    if results is None:
                        log.info("Inserindo host genérico com o IP %s", hostname)
                        try:
                            session.add(host)
                            session.flush()
                        except IntegrityError, e:
                            log.error("Erro adicionando host genérico com o IP %s. IP Repetido\n%s", hostname, e.message)

                            # Agora atualiza informações do host
                            if host.mac_address is not None:
                                session.execute(
                                    Host.__table__.update().values(
                                        mac_address=host.mac_address,
                                        name=host.name,
                                        ports=host.ports,
                                        ip_network=host.ip_network
                                    ).where(
                                        Host.network_ip == hostname
                                    )
                                )
                                session.flush()
                                log.info("Informações do host %s atualizadas com sucesso", hostname)
                    else:
                        log.info("Host genérico com o IP %s já cadastrado", hostname)

                        # Agora atualiza informações do host
                        if host.mac_address is not None:
                            session.execute(
                                Host.__table__.update().values(
                                    mac_address=host.mac_address,
                                    name=host.name,
                                    ports=host.ports,
                                    ip_network=host.ip_network
                                ).where(
                                    Host.network_ip == hostname
                                )
                            )
                            session.flush()
                            log.info("Informações do host %s atualizadas com sucesso", hostname)

                #session.flush()
            session.close()

            log.info("CARGA DO ARQUIVO DE REDE %s FINALIZADA!!!", network_file)

    def import_printers(self):
        """
        Importa impressoras já cadastradas e não presentes na base local
        :return:
        """

        cocar_url = self.cocar.config.get('cocar', 'server_url')
        printers_url = cocar_url + '/api/printer'
        result = requests.get(printers_url)
        result_json = result.json()
        session = self.cocar.Session

        for elm in result_json['printers']:
            printer = Printer(
                ip_address=elm['network_ip']
            )

            try:
                session.add(printer)
                session.flush()
            except IntegrityError as e:
                log.info("Impressora %s ja cadastrada", elm['network_ip'])

        session.close()

    def get_mac(self):
        """
        Atualiza MAC Address para o host selecionado
        :return:
        """
        if type(self.options.hosts) != list:
            self.options.hosts = [self.options.hosts]

        session = self.cocar.Session
        for host in self.options.hosts:
            arp = ArpSession(
                host=host,
                iface=self.options.iface,
                timeout=self.options.timeout
            )

            result = arp.scan()

            if result is not None:
                log.debug("Atualizando MAC = %s para  host = %s", result, host)
                session.execute(
                    Host.__table__.update().values(
                        mac_address=result
                    ).where(
                        Host.network_ip == host
                    )
                )
                session.flush()

        session.close()

    def scan_mac(self):
        """
        Scan all hosts to update macs
        """
        processes = int(self.cocar.config.get('cocar', 'processes'))
        # Create queues
        task_queue = Queue()
        done_queue = Queue()

        session = self.cocar.Session
        results = session.query(Host).all()
        for host in results:
            arp = ArpSession(
                host=host.network_ip,
                iface=self.options.iface,
                timeout=self.options.timeout
            )
            task_queue.put(arp)

        #Start worker processes
        for i in range(processes):
            Process(target=worker_mac, args=(task_queue, done_queue)).start()

        # Get and print results
        print 'Unordered results:'
        for i in range(len(results)):
            host_list = done_queue.get()
            log.debug(host_list)
            if host_list[1] is None:
                log.error("Nao foi possivel encontrar o mac do host %s", host_list[0])
                continue
            try:
                log.debug("Atualizando MAC = %s para  host = %s", host_list[1], host_list[0])
                session.execute(
                    Host.__table__.update().values(
                        mac_address=host_list[1]
                    ).where(
                        Host.network_ip == host_list[0]
                    )
                )
                session.flush()
            except AttributeError, e:
                log.error("Erro na atualização do MAC para host %s\n%s", host_list[0], e.message)
                continue

        # Tell child processes to stop
        for i in range(processes):
            task_queue.put('STOP')


def make_query(host):
    """This does the actual snmp query

    This is a bit fancy as it accepts both instances
    of SnmpSession and host/ip addresses.  This
    allows a user to customize mass queries with
    subsets of different hostnames and community strings
    """
    return host.scan()


def make_query_printer(host):
    """This does the actual snmp query

    This is a bit fancy as it accepts both instances
    of SnmpSession and host/ip addresses.  This
    allows a user to customize mass queries with
    subsets of different hostnames and community strings
    """
    return host.printer_dict()


def make_query_mac(host):
    """This does the actual snmp query

    This is a bit fancy as it accepts both instances
    of SnmpSession and host/ip addresses.  This
    allows a user to customize mass queries with
    subsets of different hostnames and community strings
    """
    return host.scan_list()


# Function run by worker processes
def worker(inp, output):
    for func in iter(inp.get, 'STOP'):
        result = make_query(func)
        output.put(result)


# Function run by worker processes
def worker_printer(inp, output):
    for func in iter(inp.get, 'STOP'):
        result = make_query_printer(func)
        output.put(result)


# Function run by worker processes
def worker_mac(inp, output):
    for func in iter(inp.get, 'STOP'):
        result = make_query_mac(func)
        output.put(result)