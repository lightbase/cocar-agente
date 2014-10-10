#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'

import unittest
import os
import os.path
import shutil
from ..session import Host, SnmpSession, NmapSession
from .. import Cocar
from ..model import network
from .. import utils


class TestDiscover(unittest.TestCase):
    """
    Testa descoberta de ativos de rede utilizando snmp
    """

    def setUp(self):
        """
        Parâmetros iniciais
        """
        self.activeip = '127.0.0.1'
        self.inactiveip = '127.1.1.1'
        self.localhost = '127.0.0.1'
        cocar = Cocar()
        self.data_dir = cocar.cocar_data_dir

        local_network = utils.get_local_network()
        self.network = network.Network(
            network_ip=str(local_network.cidr),
            name='Rede de teste'
        )

    def test_active(self):
        """
        Teste que verifica se o ativo de rede está ativo
        """
        session = SnmpSession(DestHost=self.activeip)
        result = session.query()
        print(result.query[0])
        self.assertIsNotNone(result.query[0])

    def test_inactive(self):
        """
        Teste que identifica que um ativo de rede está inativo
        """
        session = SnmpSession(DestHost=self.inactiveip)
        result = session.query()
        print(result.query[0])
        self.assertIsNone(result.query[0])

    def test_scan(self):
        """
        Teste que realiza o scan em todas as informações do ativo
        """
        session = NmapSession(self.localhost)
        result = session.scan()
        assert result

        # Tenta achar o arquivo
        outfile = self.data_dir + "/" + self.localhost + ".xml"
        assert (os.path.isfile(outfile))

    def test_scan_rede_full(self):
        """
        Realiza busca em todos os IP's da rede e grava resultados num arquivo específico
        """
        session = NmapSession(self.network.network_ip.cidr)
        session.scan()

        # List all IP's from directory
        self.assertTrue(os.path.isfile(session.outfile))

        # Apaga arquivo
        #os.unlink(session.outfile)

    def test_scan_rede(self):
        """
        Realiza busca rápida em todos os IP's da rede e grava resultados num arquivo específico
        """
        session = NmapSession(self.network.network_ip.cidr, full=False)
        session.scan()

        # List all IP's from directory
        self.assertTrue(os.path.isfile(session.outfile))

        # Apaga arquivo
        #os.unlink(session.outfile)

    def tearDown(self):
        """
        Apaga dados inicias
        """
        #shutil.rmtree(self.data_dir)