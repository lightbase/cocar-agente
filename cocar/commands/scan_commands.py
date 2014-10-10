#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'
import logging
import os
import os.path
from paste.script import command
from .. import Cocar
from ..model import Base
from ..model.network import Network
from ..csv_utils import NetworkCSV
from ..session import NmapSession
from multiprocessing import Process, Queue

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

    Os comandos devem ser executados a partir da raiz do módulo Cocar
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


def make_query(host):
    """This does the actual snmp query

    This is a bit fancy as it accepts both instances
    of SnmpSession and host/ip addresses.  This
    allows a user to customize mass queries with
    subsets of different hostnames and community strings
    """
    return host.scan()


# Function run by worker processes
def worker(inp, output):
    for func in iter(inp.get, 'STOP'):
        result = make_query(func)
        output.put(result)