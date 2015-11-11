# -*- coding: utf-8 -*-
__author__ = 'eduardo'
import logging
import sys
import time
from paste.script import command
from multiprocessing import Process, Queue
from .. import Cocar
from ..coleta import Coleta
from ..model.computer import Computer
from ..model.host import Host, HostArping

log = logging.getLogger()


class ComputerCommands(command.Command):
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
    group_name = "Computer Commands"

    parser = command.Command.standard_parser(verbose=True)

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
        '-w', '--wait',
        action='store',
        dest='wait',
        help='Wait time for exports'
    )

    def __init__(self, name):
        """
        Constructor method

        """
        super(ComputerCommands, self).__init__(name)
        self.cocar = Cocar(environment='production')

    def command(self):
        """
        Parse command line arguments and call appropriate method.
        """
        if not self.args or self.args[0] in ['--help', '-h', 'help']:
            print(ComputerCommands.__doc__)
            return

        cmd = self.args[0]

        # Timeout mínimo
        if self.options.timeout is None:
            self.options.timeout = "1000"

        if self.options.wait is None:
            self.options.wait = "300"

        if cmd == 'export_computers':
            self.export_computers()
            return

        if cmd == 'start':
            self.start()
            return

    def export_computers(self):
        """
        Exporta todos os contadores para o Cocar
        """
        session = self.cocar.Session
        results = session.query(Computer).join(
            Host.__table__,
            Host.network_ip == Computer.network_ip
        ).join(
            HostArping.__table__,
            HostArping.network_ip == Host.network_ip
        ).all()
        for computer in results:
            log.info("Exportando computador %s", computer.mac_address)
            computer.export_computer(server_url=self.cocar.config.get('cocar', 'server_url'), session=session)

        session.close()
        log.info("EXPORT DOS COMPUTADORES FINALIZADO!!! %s PING EXPORTADOS!!!", len(results))

    def start(self):
        """
        Executa as coletas de todos os ativos de rede
        """
        while True:
            try:
                self.export_computers()

                # Espera até a próxima execução
                time.sleep(int(self.options.wait))

            except KeyboardInterrupt as e:
                log.info("Finalização forçada. Saindo...")
                sys.exit(0)
