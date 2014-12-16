#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'

import unittest
import cocar.tests
import requests
import time
import json
from mock import patch
from ..xml_utils import NmapXML
from ..csv_utils import NetworkCSV
from ..model.computer import Computer
from ..model.printer import Printer, PrinterCounter
from ..model.network import Network
from . import fake_urlopen
from sqlalchemy import inspect


class TestPersistence(unittest.TestCase):
    """
    Testa identificação de ativos de rede
    """
    def setUp(self):
        """
        Carrega parâmetros iniciais
        """
        self.data_dir = cocar.tests.cocar.cocar_data_dir
        self.network_file = cocar.tests.test_dir + "/fixtures/192.168.0.0-24.xml"
        self.localhost_file = cocar.tests.test_dir + "/fixtures/127.0.0.1.xml"
        self.printer_file = cocar.tests.test_dir + "/fixtures/printer.xml"
        self.network_csv = cocar.tests.test_dir + "/fixtures/networks.csv"
        self.session = cocar.tests.cocar.Session
        self.patcher = patch('requests.put', fake_urlopen)
        self.patcher.start()

        # Rede para os testes
        self.rede = Network(
            network_ip='192.168.0.0',
            netmask='255.255.255.0',
            network_file='/tmp/network.xml',
            name='Rede de Teste'
        )
        #self.session.add(self.rede)
        #self.session.flush()

    def test_connect(self):
        """
        Testa conexão do SQLAlchemy
        """
        db_session = self.session
        self.assertIsNotNone(db_session)

    def test_persist_computer(self):
        """
        Grava computador no banco de dados
        """
        hostname = '127.0.0.1'
        nmap_xml = NmapXML(self.localhost_file)
        host = nmap_xml.parse_xml()
        assert host

        computer = nmap_xml.identify_host(hostname)
        self.assertIsInstance(computer, Computer)

        # Agora testa a persistência
        self.session.add(computer)
        self.session.flush()

        # Tenta ver se gravou
        results = self.session.query(Computer).first()
        self.assertIsNotNone(results)

    def test_persist_printer(self):
        """
        Grava impressora no banco de dados
        """
        hostname = '10.72.168.3'
        nmap_xml = NmapXML(self.printer_file)
        host = nmap_xml.parse_xml()
        assert host

        printer = nmap_xml.identify_host(hostname)
        self.assertIsInstance(printer, Printer)

        # Agora testa a persistência
        printer = self.session.merge(printer)
        self.session.flush()

        # Tenta ver se gravou
        results = self.session.query(Printer).first()
        self.assertIsNotNone(results)

    def test_persist_network(self):
        """
        Testa gravação dos dados de rede
        """
        rede = Network(
            network_ip='192.168.0.1',
            netmask='255.255.255.0',
            network_file='/tmp/network.xml',
            name='Rede de Teste'
        )
        self.session.add(rede)
        self.session.flush()

        # Tenta ver se gravou
        results = self.session.query(Network).first()
        self.assertIsNotNone(results)

        # Remove rede
        self.session.delete(rede)
        self.session.flush()

    def test_load_networks(self):
        """
        Carrega no banco redes oriundas de arquivo CSV
        """
        network_csv = NetworkCSV(csv_file=self.network_csv)
        network = network_csv.parse_csv()
        self.assertIsInstance(network[0], Network)

        for elm in network:
            self.assertIsInstance(elm, Network)
            self.session.add(elm)

        self.session.flush()
        # Tenta ver se gravou
        results = self.session.query(Network).first()
        self.assertIsNotNone(results)

        # Now remove networks
        for elm in network:
            self.assertIsInstance(elm, Network)
            self.session.delete(elm)

        self.session.flush()

        # Verifica se foi tudo removido
        results = self.session.query(Network).first()
        self.assertIsNone(results)

    def test_printer_counter(self):
        """
        Testa inserção do contador em uma impressora
        """
        hostname = '10.72.168.4'
        ports = {
            "9100": {
                "state": "open",
                "protocol": "tcp",
                "service": "vnc-http"
            },
            "631": {
                "state": "open",
                "protocol": "tcp",
                "service": "vnc-http"
            }
        }

        # Agora verifica a inserção do contador
        counter = PrinterCounter(
            ip_address=hostname,
            mac_address=None,
            hostname=None,
            inclusion_date=time.time(),
            open_ports=ports,
            scantime='3600',
            model='Samsung SCX-6x55X Series',
            serial='Z7EUBQBCB03539E',
            description='Samsung SCX-6x55X Series; V2.00.03.01 03-23-2012;Engine 0.41.69;NIC V5.01.82(SCX-6x55X) 02-28-2012;S/N Z7EUBQBCB03539E',
            counter=1280,
            counter_time=time.time(),
            ip_network=self.rede.ip_network
        )

        self.assertIsInstance(counter, PrinterCounter)
        self.assertEqual(counter.counter, 1280)
        self.assertEqual(counter.network_ip, hostname)

        counter = self.session.merge(counter)
        self.session.flush()

        # Tenta ver se gravou
        results = self.session.query(PrinterCounter).first()
        self.assertIsNotNone(results)

        # Apaga
        self.session.delete(counter)
        self.session.flush()

    def test_update_counter(self):
        """
        Testa inserção dos parâmetros do contador em impressora existente
        """
        hostname = '10.72.168.3'
        nmap_xml = NmapXML(self.printer_file)
        host = nmap_xml.parse_xml()
        assert host

        printer = nmap_xml.identify_host(hostname)
        self.assertIsInstance(printer, Printer)

        #print("111111111111111111111111111111111")
        #ins = inspect(self.rede)
        #print('Transient: {0}; Pending: {1}; Persistent: {2}; Detached: {3}'.format(ins.transient, ins.pending, ins.persistent, ins.detached))

        printer_counter = PrinterCounter(
            ip_address=printer.ip_address,
            mac_address=printer.mac_address,
            hostname=printer.hostname,
            inclusion_date=printer.inclusion_date,
            open_ports=printer.open_ports,
            scantime=printer.scantime,
            model='Samsung SCX-6x55X Series',
            serial='Z7EUBQBCB03539E',
            description='Samsung SCX-6x55X Series; V2.00.03.01 03-23-2012;Engine 0.41.69;NIC V5.01.82(SCX-6x55X) 02-28-2012;S/N Z7EUBQBCB03539E',
            counter=1280,
            counter_time=time.time(),
            ip_network=self.rede.ip_network
        )

        #self.session.add(printer_counter)
        result = printer_counter.update_counter(self.session)
        self.session.flush()
        assert result

        #result = printer_counter.update_counter(self.session)

        # Tenta ver se gravou
        results = self.session.query(PrinterCounter).first()
        self.assertIsNotNone(results)

        # Altera o contador e vê se gravou
        printer_counter.counter = 1290
        printer_counter.counter_time = time.time() + 1
        printer_counter = self.session.merge(printer_counter)
        self.session.flush()
        #result = printer_counter.update_counter(self.session)
        #print("11111111111111111111111111111")
        #print(result)
        #assert result

        # Aqui não pode inserir de novo
        result = printer_counter.update_counter(self.session)
        self.assertFalse(result)

        # Remove para finalizar o teste
        self.session.delete(printer_counter)
        self.session.flush()

    def test_export_printer(self):
        """
        Exporta a impressora para a interface do Cocar
        """
        hostname = '10.72.168.3'
        nmap_xml = NmapXML(self.printer_file)
        host = nmap_xml.parse_xml()
        assert host

        printer = nmap_xml.identify_host(hostname)
        self.assertIsInstance(printer, Printer)

        #print("111111111111111111111111111111111")
        #ins = inspect(self.rede)
        #print('Transient: {0}; Pending: {1}; Persistent: {2}; Detached: {3}'.format(ins.transient, ins.pending, ins.persistent, ins.detached))

        printer_counter = PrinterCounter(
            ip_address=printer.ip_address,
            mac_address=printer.mac_address,
            hostname=printer.hostname,
            inclusion_date=printer.inclusion_date,
            open_ports=printer.open_ports,
            scantime=printer.scantime,
            model='Samsung SCX-6x55X Series',
            serial='Z7EUBQBCB03539E',
            description='Samsung SCX-6x55X Series; V2.00.03.01 03-23-2012;Engine 0.41.69;NIC V5.01.82(SCX-6x55X) 02-28-2012;S/N Z7EUBQBCB03539E',
            counter=1280,
            counter_time=time.time(),
            ip_network=self.rede.ip_network
        )

        #self.session.add(printer_counter)
        printer_counter = self.session.merge(printer_counter)
        self.session.flush()

        result = printer_counter.update_counter(self.session)
        #assert result

        # Adiciona outro contador
        printer_counter = PrinterCounter(
            ip_address=printer.ip_address,
            mac_address=printer.mac_address,
            hostname=printer.hostname,
            inclusion_date=printer.inclusion_date,
            open_ports=printer.open_ports,
            scantime=printer.scantime,
            model='Samsung SCX-6x55X Series',
            serial='Z7EUBQBCB03539E',
            description='Samsung SCX-6x55X Series; V2.00.03.01 03-23-2012;Engine 0.41.69;NIC V5.01.82(SCX-6x55X) 02-28-2012;S/N Z7EUBQBCB03539E',
            counter=1290,
            counter_time=(time.time() + 1),
            ip_network=self.rede.ip_network
        )

        printer_counter = self.session.merge(printer_counter)
        result = printer_counter.update_counter(self.session)
        #assert result

        # Exportar a impressora deve retornar 200
        result = printer.export_printer(cocar.tests.cocar.config.get('cocar', 'server_url'), self.session)
        assert result

        # Não deve ter mais nenhum impressora na tabela
        result = self.session.query(PrinterCounter).all()
        self.assertEqual(len(result), 0)

        # Remove para finalizar o teste
        self.session.delete(printer_counter)
        self.session.flush()

    def test_import_printers(self):
        """
        Testa importação da rede
        """
        cocar_url = cocar.tests.cocar.config.get('cocar', 'server_url')
        printers_url = cocar_url + '/api/printer'
        result = requests.get(printers_url)
        self.assertEqual(result.status_code, 200)

        result_json = result.json()
        self.assertGreater(len(result_json), 0)

        i = 0
        for elm in result_json['printers']:
            i += 1
            if i > 20:
                break

            printer = Printer(
                ip_address=elm['network_ip'],
                ip_network=self.rede.ip_network
            )

            self.session.add(printer)
            self.session.flush()

            self.session.delete(printer)
            self.session.flush()

    def tearDown(self):
        """
        Remove dados
        """
        self.patcher.stop()
        self.session.close()
        pass