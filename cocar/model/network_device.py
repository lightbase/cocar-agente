#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'
import logging
import arrow
from netaddr import IPAddress
from sqlalchemy.schema import Column, ForeignKeyConstraint, ForeignKey
from sqlalchemy.types import String, Integer, UnicodeText, Boolean, DateTime
from .host import Host
from . import Base

log = logging.getLogger()


class NetworkDevice(Host):
    """
    Dispositivo de rede genérico
    """
    __tablename__ = 'network_device'
    network_ip = Column(String(16), ForeignKey("host.network_ip"), nullable=False, primary_key=True)
    service = Column(UnicodeText)
    location = Column(UnicodeText)
    contact = Column(UnicodeText)
    community = Column(UnicodeText)
    uptime = Column(UnicodeText)
    memory = Column(Integer)
    version = Column(UnicodeText)
    avg_busy1 = Column(UnicodeText)
    avg_busy5 = Column(UnicodeText)
    ip_forward = Column(Integer),
    bridge = Column(Integer)
    # TODO: Incluir parâmetros da coleta CISCO? Pensar...

    def __init__(self,
                 service=None,
                 location=None,
                 contact=None,
                 community=None,
                 uptime=None,
                 memory=None,
                 version=None,
                 avg_busy1=None,
                 avg_busy5=None,
                 ip_forward=None,
                 bridge=None,
                 *args,
                 **kwargs):
        """
        :param service: Tipo de serviço fornecido pelo ativo com a seguinte heuristica
                {
                    1: "repeater",
                    2: "bridge",
                    4: "router",
                    6: "switch",
                    8: "gateway",
                    16: "session",
                    32: "terminal",
                    64: "application"
                }
        :param community: Communit SNMP do ativo
        :param uptime: Parametro Uptime
        :param memory: Memória em MB
        :param version: Versão do SNMP
        :param avg_busy1: Utilização de CPU no último minuto
        :param avg_busy5: Utilização de CPU nos últimos 5 minutos
        """
        Host.__init__(self,  *args, **kwargs)
        self.service = service
        self.location = location
        self.contact = contact
        self.community = community
        self.uptime = uptime
        self.memory = memory
        self.version = version
        self.avg_busy1 = avg_busy1
        self.avg_busy5 = avg_busy5
        self.ip_forward = ip_forward
        self.bridge = bridge


class NetworkDeviceInterface(Base):
    """
    Interface de rede do dispositivo
    """
    __tablename__ = 'network_device_interface'
    id_interface = Column(Integer, primary_key=True, autoincrement=True)
    network_device_ip = Column(String(16), ForeignKey("network_device.network_ip"), nullable=False)
    if_index = Column(Integer)
    if_descr = Column(UnicodeText)
    description = Column(UnicodeText)
    ip = Column(String(16))
    ip_order = Column(Integer)
    if_admin_status = Column(UnicodeText)
    if_oper_status = Column(UnicodeText)
    last_change = Column(DateTime, default=arrow.now().datetime)
    if_mac = Column(UnicodeText)

    def __init__(self,
                 if_index=None,
                 if_descr=None,
                 description=None,
                 ip=None,
                 ip_order=None,
                 if_admin_status=None,
                 if_oper_status=None,
                 last_change=None,
                 if_mac=None
                 ):
        """
        :param if_index: Índice da interface de rede no dispositivo
        :param if_descr: Tipo de interface
        :param description: Descrição da interface
        :param ip: Endereço IP
        :param ip_order: Ordem do dispositivo
        :param if_admin_status: Admin status
        :param if_oper_status: Oper status
        :param last_change: Data da última alteração
        :param if_mac: MAC Address
        """
        self.if_index = if_index
        self.if_descr = if_descr
        self.description = description
        self.ip = ip
        self.ip_order = ip_order
        self.if_admin_status = if_admin_status
        self.if_oper_status = if_oper_status
        self.last_change = last_change
        self.if_mac = if_mac
