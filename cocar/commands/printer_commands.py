# -*- coding: utf-8 -*-
__author__ = 'eduardo'
import logging
import time
import requests
import sys
from paste.script import command
from .. import Cocar
from ..model.printer import Printer, PrinterCounter
from multiprocessing import Process, Queue
from ..session import SnmpSession
from sqlalchemy.exc import IntegrityError, ProgrammingError

log = logging.getLogger()


class PrinterCommands(command.Command):
    """
    Comandos para realizar a coleta das impressoras

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
    group_name = "Printer Commands"

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

    def __init__(self, name):
        """
        Constructor method

        """
        super(PrinterCommands, self).__init__(name)
        self.cocar = Cocar(environment='production')

    def command(self):
        """
        Parse command line arguments and call appropriate method.
        """

        if not self.args or self.args[0] in ['--help', '-h', 'help']:
            print(PrinterCommands.__doc__)
            return

        cmd = self.args[0]

        if cmd == 'get_printers':
            self.get_printers()
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
        if cmd == 'import_printers':
            self.import_printers()
            return

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
            # printer.network_ip = printer.ip_network
            snmp_session = SnmpSession(
                DestHost=printer.network_ip,
                Timeout=self.options.timeout
            )
            if snmp_session is None:
                log.error("Erro na coleta SNMP da impressora %s", printer.network_ip)
                continue
            else:
                task_queue.put(snmp_session)

        # Start worker processes
        for i in range(processes):
            Process(target=PrinterCommands.worker_printer, args=(task_queue, done_queue)).start()

        # Get and print results
        log.debug('Unordered results:')
        for i in range(len(results)):
            printer_dict = done_queue.get()
            log.debug(printer_dict)
            if printer_dict['counter'] is None:
                log.error("Nao foi possivel ler o contador da impressora %s", printer_dict['network_ip'])
                continue

            if printer_dict['serial'] is None:
                log.error("Serial vazio para a impressora %s. Desconsiderar...", printer_dict['network_ip'])
                continue

            try:
                log.debug("Gravando contador = %s para a impressora = %s serial = %s",
                          printer_dict['counter'], printer_dict['network_ip'], printer_dict['serial'])

                results = session.query(Printer.__table__).filter(
                    Printer.__table__.c.serial == printer_dict['serial']
                ).first()

                if results is None:
                    # Tenta encontrar pelo IP
                    results = session.query(Printer.__table__).filter(
                        Printer.__table__.c.network_ip == printer_dict['network_ip']
                    ).first()

                    if results is not None:
                        # Atualiza o serial
                        log.debug("Atualizando serial %s para a impressora com IP %s",
                                  printer_dict['serial'], printer_dict['network_ip'])
                        session.execute(
                            Printer.__table__.update().values(
                                serial=printer_dict['serial']
                            ).where(
                                Printer.__table__.c.network_ip == printer_dict['network_ip']
                            )
                        )
                        session.flush()

                printer = PrinterCounter(
                    ip_address=printer_dict['network_ip'],
                    model=printer_dict['model'],
                    serial=printer_dict['serial'],
                    description=printer_dict['description'],
                    counter=printer_dict['counter'],
                    counter_time=time.time()
                )
                printer.update_counter(session)
            except AttributeError as e:
                log.error("Erro na insercao do contador para a impressora %s\n%s", printer_dict['network_ip'], e.message)
                continue

            except UnicodeDecodeError as e:
                log.error("Caracteres invalidos\n%s", e.message)
                continue

            except ProgrammingError as e:
                log.error("Serial com caracteres invalidos\n%s", e.message)
                continue

            except IntegrityError as e:
                log.error("Erro impossível de serial que já existe\n%s", e.message)
                continue

        # Tell child processes to stop
        for i in range(processes):
            task_queue.put('STOP')

    def export_printers(self):
        """
        Exporta todos os contadores para o Cocar
        """
        session = self.cocar.Session
        results = session.query(Printer).join(
            PrinterCounter.__table__,
            PrinterCounter.serial == Printer.serial
        ).all()
        for printer in results:
            log.info("Exportando impressora %s", printer.serial)
            printer.export_printer(server_url=self.cocar.config.get('cocar', 'server_url'), session=session)

        session.close()
        log.info("EXPORT DAS IMPRESSORAS FINALIZADO!!! %s IMPRESSORAS EXPORTADAS!!!", len(results))

    def get_printer_attribute(self):
        """
        Retorna e grava um atributo no valor da impressora
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
            # printer.network_ip = printer.ip_network
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
                #log.debug(printer_dict)
                try:
                    log.debug("Atualizando informacoes da impressora %s", printer.network_ip)
                    log.debug(printer_dict)

                    if printer_dict.get('counter') is not None:

                        printer_counter = PrinterCounter(
                            ip_address=printer.network_ip,
                            serial=printer_dict['serial'],
                            counter=printer_dict['counter'],
                            counter_time=time.time()
                        )

                        if printer_dict.get('model') is not None:
                            printer_counter.model = printer_dict['model']
                            printer.model = printer_dict['model']

                        if printer_dict.get('description') is not None:
                            printer_counter.description = printer_dict['description']
                            printer.description = printer_dict['description']

                        # Para esse caso atualiza o contador
                        printer_counter.update_counter(session)
                    else:
                        # Não posso seguir sem serial
                        printer.serial = printer_dict['serial']

                        # Nesse caso só atualizo a impressora
                        if printer_dict.get('model') is not None:
                            printer.model = printer_dict['model']

                        if printer_dict.get('description') is not None:
                            printer.description = printer_dict['description']

                    session.execute(
                        Printer.__table__.update().values(
                            network_ip=printer.network_ip,
                            model=printer.model,
                            description=printer.description
                        ).where(
                            Printer.__table__.c.serial == printer.serial
                        )
                    )
                    session.flush()

                except IntegrityError as e:
                    log.error("Erro na atualizacao das informacoes para a impressora %s\n%s", printer.network_ip, e.message)
                    continue

                except KeyError as e:
                    log.error("Serial não localizado para a impressora %s\n%s", printer.network_ip, e.message)
                    continue

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
                ip_address=elm['host'],
                serial=elm['serie']
            )

            try:
                session.add(printer)
                session.flush()
            except IntegrityError as e:
                log.info("Impressora %s ja cadastrada", elm['host'])

        session.close()

    def printer_scan(self):
        """
        Fica varrendo a rede e tenta encontrar as impressoras a cada 10min
        """
        while True:
            try:
                self.import_printers()
                log.info("FIM DO IMPORT DAS IMPRESSORAS!!! Iniciando coletas...")

                self.get_printers()
                log.info("SCAN DE IMPRESSORAS FINALIZADO!!! Iniciando export de coletores")

                self.export_printers()
                log.info("EXPORT DE IMPRESSORAS FINALIZADO!!! Reiniciando as coletas")
                #time.sleep(600)
            except KeyboardInterrupt as e:
                log.info("IMPRESSORAS - Finalização forçada. Saindo...")
                sys.exit(0)

    @staticmethod
    def make_query_printer(host):
        """This does the actual snmp query

        This is a bit fancy as it accepts both instances
        of SnmpSession and host/ip addresses.  This
        allows a user to customize mass queries with
        subsets of different hostnames and community strings
        """
        return host.printer_dict()

    # Function run by worker processes
    @staticmethod
    def worker_printer(inp, output):
        for func in iter(inp.get, 'STOP'):
            result = PrinterCommands.make_query_printer(func)
            output.put(result)
