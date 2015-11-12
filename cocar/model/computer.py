#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'
import logging
from sqlalchemy.schema import Column
from sqlalchemy.types import *
from sqlalchemy import ForeignKey
from .host import Host, HostArping

log = logging.getLogger()


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
        super(Computer, self).__init__(*args, **kwargs)
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

    def __repr__(self):
        """
        Lista atributos da classe
        """
        return "<Computer('%s, %s, %s, %s, %s, %s, %s, %s')>" % (
            self.network_ip,
            self.so_name,
            self.so_version,
            self.accuracy,
            self.so_vendor,
            self.so_os_family,
            self.so_type,
            self.so_cpe
        )

    def export_computer(self, server_url, session):
        """
        Exporta todos os contadores para a impressora
        """
        counter_list = session.query(HostArping).all()

        for counter in counter_list:
            #print(counter)
            server_url += '/api/computer/'
            dados = {
                'so_name': self.so_name,
                'so_version': self.so_version,
                'accuracy': self.accuracy,
                'so_vendor': self.so_vendor,
                'so_os_family': self.so_os_family,
                'so_type': self.so_type,
                'so_cpe': self.so_cpe
            }
            result = counter.export_ping(server_url, session, dados)
            if result:
                log.info("Ping em %s para o computador %s exportado com sucesso", counter.ping_date, self.mac_address)
            else:
                log.error("Erro na remocao do ping %s para o computador %s", counter.ping_date, self.serial)
                return False

        log.info("EXPORT DO COMPUTADOR %s FINALIZADO!!! %s PING EXPORTADOS!!!", self.mac_address, len(counter_list))
        return True
