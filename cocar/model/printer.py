#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'

from .host import Host
from sqlalchemy import ForeignKey
from sqlalchemy.schema import Column
from sqlalchemy.types import String, Integer


class Printer(Host):
    """
    Classe que identifica uma impressora
    """
    __tablename__ = 'printer'
    network_ip = Column(String(16), ForeignKey("host.network_ip"), nullable=False, primary_key=True)
    counter = Column(Integer)
    serial = Column(String(50))
    description = Column(String)

    def __init__(self,
                 counter=None,
                 model=None,
                 serial=None,
                 description=None,
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
        self.description = description