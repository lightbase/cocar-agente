#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'
from sqlalchemy.schema import Column
from sqlalchemy.types import *
from sqlalchemy import ForeignKey
from .host import Host


class Computer(Host):
    """
    Ativo de rede identificado como estação de trabalho
    """
    __tablename__ = 'computador'
    network_ip = Column(String(16), ForeignKey("host.network_ip"), nullable=False, primary_key=True)
    so_name = Column(String)
    so_version = Column(String)
    accuracy = Column(Integer)

    def __init__(self,
                 so,
                 *args,
                 **kwargs
                 ):
        """
        Classe que identifica uma estação de trabalho
        :param so: Sistema Operacional encontrado
        """
        Host.__init__(self, *args, **kwargs)
        self.so = so

        #SQLAlchemy parameters
        os_elm = self.so.items()[0]
        self.so_name = os_elm[1]['osfamily']
        self.so_version = os_elm[1]['version']
        self.accuracy = os_elm[1]['accuracy']