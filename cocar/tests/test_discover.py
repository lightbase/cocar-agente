#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'

import unittest
from ..host import Host, SnmpSession


class TestDiscover(unittest.TestCase):
    """
    Testa descoberta de ativos de rede utilizando snmp
    """

    def setUp(self):
        """
        Parâmetros iniciais
        """

    def test_active(self):
        """
        Teste que verifica se o ativo de rede está ativo
        """
        session = SnmpSession()
        result = session.query()
        print(result.query[0])
        self.assertIsNotNone(result.query[0])

    def test_inactive(self):
        """
        Teste que identifica que um nó inativo
        """
        session = SnmpSession(DestHost="192.168.0.201")
        result = session.query()
        print(result.query[0])
        self.assertIsNone(result.query[0])

    def test_identify(self):
        """
        Teste que identifica qual é o ativo
        """

    def tearDown(self):
        """
        Apaga dados inicias
        """