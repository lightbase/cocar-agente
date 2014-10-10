#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'

import unittest
import cocar.tests
from ..xml_utils import NmapXML
from ..model.computer import Computer
from ..model.printer import Printer
from ..model.network import Network


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
        self.session = cocar.tests.cocar.Session

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
        self.session.add(printer)
        self.session.flush()

        # Tenta ver se gravou
        results = self.session.query(Printer).first()
        self.assertIsNotNone(results)

    def test_persist_network(self):
        """
        Testa gravação dos dados de rede
        """
        rede = Network(
            network_ip='192.168.0.0',
            netmask='255.255.255.0',
            network_file='/tmp/network.xml',
            name='Rede de Teste'
        )
        self.session.add(rede)
        self.session.flush()

        # Tenta ver se gravou
        results = self.session.query(Network).first()
        self.assertIsNotNone(results)

    def tearDown(self):
        """
        Remove dados
        """
        self.session.close()
        pass