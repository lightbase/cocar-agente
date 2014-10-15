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
from ..session import NmapSession, SnmpSession
from multiprocessing import Process, Queue
from ..xml_utils import NmapXML
from sqlalchemy.exc import IntegrityError

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
        networks_csv = NetworkCSV(csv_file=self.networks_csv)
        session = self.cocar.Session
        for elm in networks_csv.parse_csv():
            results = session.query(Network).filter(Network.ip_network == elm.ip_network).first()
            if results is None:
                log.info("Adicionando a rede: %s", elm.network_ip)
                session.add(elm)
            else:
                log.info("Rede já cadastrada: %s", elm.network_ip)
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
            if self.options.full is None:
                nmap_session = NmapSession(
                    network.network_ip.cidr,
                    outfile=self.networks_dir + "/" + str(network.network_ip.cidr).replace("/", "-") + ".xml",
                    full=False
                )
            else:
                nmap_session = NmapSession(
                    network.network_ip.cidr,
                    outfile=self.networks_dir + "/" + str(network.network_ip.cidr).replace("/", "-") + ".xml",
                    full=True
                )
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
        onlyfiles = [ f for f in os.listdir(self.networks_dir) if os.path.isfile(os.path.join(self.networks_dir, f)) ]
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

    def export_printers(self):
        """
        Exporta todos os contadores para o Cocar
        """
        session = self.cocar.Session
        results = session.query(Printer).all()
        for printer in results:
            log.info("Exportando impressora %s", printer.network_ip)
            printer.export_printer(server_url=self.cocar.config.get('cocar', 'server_url'), session=session)

        session.close()

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
        onlyfiles = list()
        if type(self.options.networks) == list:
            for elm in self.options.networks:
                onlyfiles.append(elm)
        else:
            onlyfiles.append(self.options.networks)

        for i in range(len(onlyfiles)):
            network_file = self.networks_dir + "/" + onlyfiles[i]
            log.info("Processando arquivo de rede %s", network_file)
            nmap_xml = NmapXML(network_file)
            try:
                host_dict = nmap_xml.parse_xml()
            except AttributeError, e:
                log.error("Erro realizando parsing do arquivo %s\n%s", network_file, e.message)
                continue
            except lxml.etree.XMLSyntaxError, e:
                log.error("Erro realizando parsing do arquivo %s\n%s", network_file, e.message)
                continue

            if not host_dict:
                log.error("File %s not found", network_file)
                continue
            session = self.cocar.Session
            for hostname in nmap_xml.hosts.keys():
                host = nmap_xml.identify_host(hostname, timeout=self.options.timeout)
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
                                session.flush()
                                log.info("Impressora %s adicionada novamente com sucesso", hostname)
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
                    else:
                        log.info("Computador com o IP %s já cadastrado", hostname)
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
                    else:
                        log.info("Host genérico com o IP %s já cadastrado", hostname)

                #session.flush()
            session.close()

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
            except IntegrityError, e:
                log.info("Impressora %s ja cadastrada", elm['network_ip'])

        session.close()


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