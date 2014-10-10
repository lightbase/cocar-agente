#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'

import unittest
import json
import cocar.tests
from ..xml_utils import NmapXML
from ..model.computer import Computer
from ..model.printer import Printer


class TestIdentify(unittest.TestCase):
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

    def test_parse_xml(self):
        """
        Faz o parsing do XML da rede e transforma em dicionário
        """
        nmap_xml = NmapXML(self.localhost_file)
        host = nmap_xml.parse_xml()
        assert host

        # Check for parsing keys
        hostname = '127.0.0.1'
        fd = open('/tmp/teste-network.json', 'w+')
        fd.write(json.dumps(nmap_xml.hosts, ))
        fd.close()
        self.assertGreater(len(nmap_xml.hosts[hostname].keys()), 0)
        print(nmap_xml.hosts[hostname].keys())
        self.assertGreater(len(nmap_xml.hosts[hostname]['hostname']), 0)
        self.assertGreater(len(nmap_xml.hosts[hostname]['ports']), 0)
        self.assertGreater(len(nmap_xml.hosts[hostname]['os']), 0)
        #self.assertGreater(len(nmap_xml.hosts[hostname]['mac']), 0)

    def test_identify_computer(self):
        """
        Testa identificação do host
        """
        hostname = '127.0.0.1'
        nmap_xml = NmapXML(self.localhost_file)
        # Aqui tem que dar erro porque ainda não mandei carregar o XML
        with self.assertRaises(AttributeError):
            nmap_xml.identify_host(hostname)

        # Aqui eu verifico se foi possível identificar o host
        host = nmap_xml.parse_xml()
        assert host
        computer = nmap_xml.identify_host(hostname)
        self.assertIsInstance(computer, Computer)

        # Se é um computer, tenho que identificar o SO
        self.assertEqual(computer.so_name, 'Linux')
        self.assertEqual(computer.so_version, 'Linux 3.7 - 3.9')
        self.assertEqual(computer.accuracy, '98')

    def test_identify_printer(self):
        """
        Identifica impressora a partir de arquivo XML
        """
        hostname = '10.72.168.3'
        nmap_xml = NmapXML(self.printer_file)
        host = nmap_xml.parse_xml()
        assert host

        printer = nmap_xml.identify_host(hostname)
        self.assertIsInstance(printer, Printer)

    def tearDown(self):
        """
        Apaga parâmetros de teste
        """