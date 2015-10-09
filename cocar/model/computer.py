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
    so_vendor = Column(String)
    so_os_family = Column(String)
    so_type = Column(String)
    so_cpe = Column(String)

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

        # SQLAlchemy parameters
        self.so_name = self.so['so_name']
        self.accuracy = self.so['accuracy']

        # Optional parameters
        self.so_version = self.so.get('version')
        self.so_vendor = self.so.get('vendor')
        self.so_os_family = self.so.get('os_family')
        self.so_type = self.so.get('type')
        self.so_cpe = self.so.get('cpe')
