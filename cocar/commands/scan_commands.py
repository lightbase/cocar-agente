#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'
import logging
import os
import sys
import os.path
import lxml.etree
import time
import pickle
import requests
import arrow
from paste.script import command
from .. import Cocar
from ..model import Base
from ..model.network import Network
from ..model.printer import Printer, PrinterCounter
from ..model.host import Host, HostArping
from ..model.computer import Computer
from ..model.network_device import NetworkDevice
from ..csv_utils import NetworkCSV
from ..session import NmapSession, SnmpSession, ArpSession
from multiprocessing import Process, Queue
from ..xml_utils import NmapXML
from sqlalchemy.exc import IntegrityError
from sqlalchemy import and_
from netaddr.core import AddrFormatError
from requests.exceptions import HTTPError

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

    parser.add_option(
        '-f', '--full',
        action='store',
        dest='full',
        help='Full scan or regular scan'
    )

    parser.add_option(
        '-i', '--ip',
        action='store',
        dest='hosts',
        help='Hosts list to scan'
    )

    parser.add_option(
        '-q', '--query',
        action='store',
        dest='query',
        help='SNMP query to execute'
    )

    parser.add_option(
        '-t', '--timeout',
        action='store',
        dest='timeout',
        help='Timeout da consulta SNMP'
    )

    parser.add_option(
        '-n', '--networks',
        action='store',
        dest='networks',
        help='Arquivo individual de rede para ser carregado'
    )

    parser.add_option(
        '-a', '--iface',
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
        if cmd == 'load_file':
            self.load_file()
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
        if cmd == 'start':
            self.start()
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
        # networks_csv = NetworkCSV(csv_file=self.networks_csv)
        # First download Networks from Cocar
        url = self.cocar.config.get('cocar', 'server_url') + '/api/networks'
        response = requests.get(
            url
        )

        try:
            # Check if request has gone wrong
            response.raise_for_status()
        except HTTPError as e:
            log.error("Erro na carga das subredes\n%s", e.message)
            return

        networks_json = response.json()
        session = self.cocar.Session

        # Primeiro apaga todas as subredes
        session.execute(
            Network.__table__.delete()
        )

        # Agora insere todas as subredes que forem encontradas
        for elm in networks_json['networks']:
            try:
                network = Network(
                    network_ip=elm['ip_network'],
                    netmask=elm['netmask'],
                    name=elm['name']
                )
            except AddrFormatError as e:
                log.error("Endereco de rede invalido!!!\n%s\n%s", elm, e.message)
                continue

            log.info("Adicionando a rede: %s", network.ip_network)
            try:
                session.add(network)
                session.flush()
            except IntegrityError as e:
                log.error("Rede repetida: %s\n%s", elm['ip_network'], e.message)
                continue

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
        print 'Resultado do Scan:'
        log.debug('Resultado do Scan:')
        for i in range(len(results)):
            output = done_queue.get()
            print ('\t Host: %s \t Resultado: %s' % (output['host'], output['result']))
            log.debug('\t Host: %s \t Resultado: %s' % (output['host'], output['result']))

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

    def scan_mac_all(self):
        """
        Fica varrendo a rede tentando arrumar os MAC's
        """
        print("*** Aperte CTRL+C para encerrar a execução ***")

        while True:
            try:
                self.scan_mac()
                log.info("SCAN DE MAC FINALIZADO!!!")
            except KeyboardInterrupt as e:
                log.info("Execução interrompida! Finalizando...")
                sys.exit(0)

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
            host_dict = dict()
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
                log.error("Arquivo nao encontrado!!! "
                          "Arquivo %s nao encontrado\n%s", network_file, e.message)

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
                    PrinterCounter.serial == Printer.serial
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
                            host = session.merge(host)
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
                                else:
                                    session.execute(
                                        Host.__table__.update().values(
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
                        log.info("Impressora com o IP %s já cadastrada. Atualizando informações da subrede", hostname)
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
                        else:
                            session.execute(
                                Host.__table__.update().values(
                                    name=host.name,
                                    ports=host.ports,
                                    ip_network=host.ip_network
                                ).where(
                                    Host.network_ip == hostname
                                )
                            )
                        #results.ip_network = host.ip_network
                        #results.network_ip = host.network_ip
                        #host = session.merge(results)
                        session.flush()
                elif isinstance(host, NetworkDevice):
                    # Vê se o host já está na base
                    results = session.query(NetworkDevice).filter(NetworkDevice.network_ip == hostname).first()
                    if results is None:
                        log.info("Inserindo computador com o IP %s", hostname)
                        try:
                            session.merge(host)
                            session.flush()
                        except IntegrityError as e:
                            log.error("Erro adicionando computador com o IP %s. IP Repetido\n%s", hostname, e.message)
                            # Pode haver um host cadastrado que não havia sido identificado como computador
                            teste = session.query(Host).filter(Host.network_ip == hostname).first()
                            if teste is not None:
                                # Adiciona o computador
                                session.execute(
                                    NetworkDevice.__table__.insert().values(
                                        network_ip=hostname,
                                        service=host.service,
                                        community=host.community
                                    )
                                )
                                log.info("NetworkDevice %s adicionado novamente com sucesso", hostname)

                                # Agora atualiza informações do host
                                if host.mac_address is not None:
                                    session.execute(
                                        Host.__table__.update().values(
                                            mac_address=host.mac_address,
                                            scantime=host.scantime,
                                            name=host.name,
                                            ports=host.ports,
                                            ip_network=host.ip_network
                                        ).where(
                                            Host.network_ip == hostname
                                        )
                                    )
                                    session.flush()
                                else:
                                    session.execute(
                                        Host.__table__.update().values(
                                            scantime=host.scantime,
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
                elif isinstance(host, Computer):
                    # Vê se o host já está na base
                    results = session.query(Computer).filter(Computer.network_ip == hostname).first()
                    if results is None:
                        log.info("Inserindo computador com o IP %s", hostname)
                        try:
                            session.merge(host)
                            session.flush()
                        except IntegrityError as e:
                            log.error("Erro adicionando computador com o IP %s. IP Repetido\n%s", hostname, e.message)
                            # Pode haver um host cadastrado que não havia sido identificado como computador
                            teste = session.query(Host).filter(Host.network_ip == hostname).first()
                            if teste is not None:
                                # Adiciona o computador
                                session.execute(
                                    Computer.__table__.insert().values(
                                        network_ip=hostname,
                                        so_name=host.so_name,
                                        so_version=host.so_version,
                                        accuracy=host.accuracy,
                                        so_vendor=host.so_vendor,
                                        so_os_family=host.so_os_family,
                                        so_type=host.so_type,
                                        so_cpe=host.so_cpe
                                    )
                                )
                                log.info("Computador %s adicionado novamente com sucesso", hostname)

                                # Agora atualiza informações do host
                                if host.mac_address is not None:
                                    session.execute(
                                        Host.__table__.update().values(
                                            mac_address=host.mac_address,
                                            scantime=host.scantime,
                                            name=host.name,
                                            ports=host.ports,
                                            ip_network=host.ip_network
                                        ).where(
                                            Host.network_ip == hostname
                                        )
                                    )
                                    session.flush()
                                else:
                                    session.execute(
                                        Host.__table__.update().values(
                                            scantime=host.scantime,
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
                host = HostArping(
                    mac_address=result,
                    network_ip=host,
                    ping_date=arrow.now().datetime
                )
                host.update_ping(session)

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
            host_result = done_queue.get()
            if host_result['result']:
                try:
                    # Adiciona entrada de ping
                    host = HostArping(
                        mac_address=host_result['mac'],
                        network_ip=host_result['host'],
                        ping_date=arrow.now().datetime
                    )
                    host.update_ping(session)

                except AttributeError as e:
                    log.error("Erro na operação de ping para o host %s\n%s", host_result['host'], e.message)
                    continue

        # Tell child processes to stop
        for i in range(processes):
            task_queue.put('STOP')

    def start(self):
        """
        Fica varrendo a rede até parar por execução forçada
        """
        while True:
            try:
                log.info("Carregando informações das subredes...")
                self.load_networks()

                log.info("Iniciando scan de redes...")
                self.scan_networks()

                log.info("Scan de redes finalizado. Iniciando procedimento de "
                         "identificação de ativos de rede, computadores e impressoras")

                self.load_network_files()
                log.info("SCAN DE REDE COMPLETO FINALIZADO!!!")
            except KeyboardInterrupt as e:
                log.info("Finalização forçada. Saindo...")
                sys.exit(0)


def make_query(host):
    """This does the actual snmp query

    This is a bit fancy as it accepts both instances
    of SnmpSession and host/ip addresses.  This
    allows a user to customize mass queries with
    subsets of different hostnames and community strings
    """
    return {
        'result': host.scan(),
        'host': host.host
    }


def make_query_mac(host):
    """This does the actual snmp query

    This is a bit fancy as it accepts both instances
    of SnmpSession and host/ip addresses.  This
    allows a user to customize mass queries with
    subsets of different hostnames and community strings
    """
    mac = host.scan()
    if mac is None:
        # Não conseguiu encontrar o MAC. Só pinga
        result = host.ping()
    else:
        result = True

    return {
        'result': result,
        'host': host.host,
        'mac': mac
    }


# Function run by worker processes
def worker(inp, output):
    for func in iter(inp.get, 'STOP'):
        result = make_query(func)
        output.put(result)


# Function run by worker processes
def worker_mac(inp, output):
    for func in iter(inp.get, 'STOP'):
        result = make_query_mac(func)
        output.put(result)
