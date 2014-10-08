#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'

from .host import Host


class Printer(Host):
    """
    Classe que identifica uma impressora
    """
    def __init__(self,
                 counter,
                 model=None,
                 serial=None
                 ):
        """
        :param counter: Contador da impressora
        :param model: Modelo da impressora
        :param serial: Número de série da impressora
        """
        Host.__init__(self)
        self.counter = counter
        self.model = model
        self.serial = serial