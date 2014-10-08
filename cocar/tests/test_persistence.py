#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'

import unittest
import cocar.tests
from ..xml_utils import NmapXML
from ..model.computer import Computer


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

    def test_connect(self):
        """
        Testa conexão do SQLAlchemy
        """
        db_session = cocar.tests.cocar.session
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

    def tearDown(self):
        """
        Remove dados
        """
        pass