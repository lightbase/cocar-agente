# -*- coding: utf-8 -*-
__author__ = 'eduardo'
import logging
import sys
from paste.script import command
from multiprocessing import Process, Queue
from .. import Cocar
from ..coleta import Coleta
from ..model.network_device import NetworkDevice, NetworkDeviceInterface

log = logging.getLogger()


class NetworkDeviceCommands(command.Command):
    """
    Comandos para realizar a coleta dos dispositivos de rede

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
    group_name = "Network Device Commands"

    parser = command.Command.standard_parser(verbose=True)

    parser.add_option(
        '-f', '--full',
        action='store',
        dest='full',
        help='Full scan or regular scan'
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
        '-i', '--ip',
        action='store',
        dest='hosts',
        help='Hosts list to scan'
    )

    parser.add_option(
        '-c', '--cisco',
        action='store',
        dest='cisco',
        help='Enable cisco attributes search'
    )

    def __init__(self, name):
        """
        Constructor method

        """
        super(NetworkDeviceCommands, self).__init__(name)
        self.cocar = Cocar(environment='production')

    def command(self):
        """
        Parse command line arguments and call appropriate method.
        """
        if not self.args or self.args[0] in ['--help', '-h', 'help']:
            print(NetworkDeviceCommands.__doc__)
            return

        cmd = self.args[0]

        # Timeout mínimo
        if self.options.timeout is None:
            self.options.timeout = "1000"

        # Desabilita cisco por padrão
        if self.options.cisco is None:
            self.options.cisco = False

        if cmd == 'coleta_snmp':
            self.coleta_snmp()
            return

        if cmd == 'identify_host':
            self.identify_host()
            return

    def identify_host(self):
        """
        Identifica host utilizando o serviço
        """
        if self.options.hosts is None:
            print("O parâmetro hosts (-i) é obrigatório")
            return
        elif type(self.options.hosts) != list:
            self.options.hosts = [self.options.hosts]

        for host in self.options.hosts:
            snmp_session = Coleta(
                DestHost=host,
                Timeout=self.options.timeout
            )

            if snmp_session is None:
                log.error("Erro na coleta SNMP do host %s", host)
                continue
            else:
                result = snmp_session.identify_host()
                if result is not None:
                    print("HOST = %s SERVICE = %s" % (host, result))
                else:
                    print("Nenhum serviço identificado para o host %s" % host)

    def coleta_snmp(self):
        """
        Coleta geral SNMP do dispositivo
        """
        session = self.cocar.Session
        if self.options.hosts is None:
            print("O parâmetro hosts (-i) é obrigatório")
            return
        elif type(self.options.hosts) != list:
            self.options.hosts = [self.options.hosts]

        processes = int(self.cocar.config.get('cocar', 'processes'))
        # Create queues
        task_queue = Queue()
        done_queue = Queue()

        for host in self.options.hosts:
            snmp_session = Coleta(
                DestHost=host,
                Timeout=self.options.timeout
            )

            if snmp_session is None:
                log.error("Erro na coleta SNMP do host %s", host)
                continue
            else:
                task_queue.put(snmp_session)

        # Start worker processes
        for i in range(processes):
            Process(target=self.worker_coleta, args=(task_queue, done_queue)).start()

        # Get and print results
        log.debug('Unordered results:')
        for i in range(len(self.options.hosts)):
            result_tuple = done_queue.get()
            if result_tuple is not None:
                # Primeiro tenta encontrar o dispositivo de rede ou Host
                results = session.query(NetworkDevice.__table__).filter(
                    NetworkDevice.__table__.c.network_ip == result_tuple[10]
                ).first()

                if results is None:
                    log.debug("Adicionando novo dispositivo de rede para o IP %s" % result_tuple[10])
                    # Armazena o novo dispositivo de rede
                    device = NetworkDevice(
                        service=result_tuple[0],
                        uptime=result_tuple[1],
                        version=result_tuple[2],
                        location=result_tuple[3],
                        contact=result_tuple[4],
                        avg_busy1=result_tuple[5],
                        avg_busy5=result_tuple[6],
                        memory=result_tuple[7],
                        ip_forward=result_tuple[8],
                        bridge=result_tuple[9],
                        ip_address=result_tuple[10]
                    )
                    session.add(device)
                    session.flush()
                else:
                    # Atualiza para valores encontrados
                    NetworkDevice.__table__.update().values(
                        service=result_tuple[0],
                        uptime=result_tuple[1],
                        version=result_tuple[2],
                        location=result_tuple[3],
                        contact=result_tuple[4],
                        avg_busy1=result_tuple[5],
                        avg_busy5=result_tuple[6],
                        memory=result_tuple[7],
                        ip_forward=result_tuple[8],
                        bridge=result_tuple[9]
                    ).where(
                        NetworkDevice.__table__.c.network_ip == result_tuple[10]
                    )
                    session.flush()

        # Tell child processes to stop
        for i in range(processes):
            task_queue.put('STOP')

    def make_query_coleta(self, host):
        """This does the actual snmp query

        This is a bit fancy as it accepts both instances
        of SnmpSession and host/ip addresses.  This
        allows a user to customize mass queries with
        subsets of different hostnames and community strings
        """
        return host.get_general(self.options.cisco)

    # Function run by worker processes
    def worker_coleta(self, inp, output):
        for func in iter(inp.get, 'STOP'):
            result = self.make_query_coleta(func)
            output.put(result)

    def coleta_devices(self):
        """
        Executa a coleta de todos os dispositivos de rede
        """
        session = self.cocar.Session
        self.options.hosts = list()
        results = session.query(NetworkDevice).all()
        for device in results:
            self.options.hosts.append(device.network_ip)

        # Executa a coleta dos dispositivos
        self.coleta_snmp()

    def start(self):
        """
        Executa as coletas de todos os ativos de rede
        """
        while True:
            try:
                self.coleta_devices()

            except KeyboardInterrupt as e:
                log.info("Finalização forçada. Saindo...")
                sys.exit(0)
