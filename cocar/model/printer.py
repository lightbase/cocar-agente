#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'

from .host import Host


class Printer(Host):
    """
    Classe que identifica uma impressora
    """
    def __init__(self,
                 counter=None,
                 model=None,
                 serial=None,
                 *args,
                 **kwargs
                 ):
        """
        :param counter: Contador da impressora
        :param model: Modelo da impressora
        :param serial: Número de série da impressora
        """
        Host.__init__(self,  *args, **kwargs)
        self.counter = counter
        self.model = model
        self.serial = serial