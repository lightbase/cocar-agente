#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'
import arrow
import logging
import json
import requests
from requests.exceptions import HTTPError
from netaddr import IPAddress
from sqlalchemy.schema import Column, ForeignKeyConstraint, ForeignKey
from sqlalchemy.types import String, Integer, DateTime
from sqlalchemy import and_, insert, update
from . import Base
from .network import Network

log = logging.getLogger()


class Host(Base):
    """
    Classe que define um ativo de rede
    """
    __tablename__ = 'host'
    network_ip = Column(String(16), primary_key=True, nullable=False)
    mac_address = Column(String(18), nullable=True, unique=True)
    name = Column(String)
    inclusion_date = Column(String(20))
    scantime = Column(Integer)
    ports = Column(String)
    ip_network = Column(String(16), ForeignKey('network.ip_network'), nullable=True)

    def __init__(self,
                 ip_address,
                 mac_address=None,
                 hostname=None,
                 inclusion_date=None,
                 scantime=None,
                 open_ports=None,
                 ip_network=None):
        """
        Método construtor do ativo de rede

        :param ip_address: Endereço Ip
        :param mac_address: MAC
        :param hostname: Nome do host
        :param inclusion_date: Data de coleta
        :param scantime: Tempo levado na execução
        :param open_ports: Portas abertas
        :param ip_network: Rede cadastrada
        :return:
        """
        self.ip_address = IPAddress(ip_address)
        self.mac_address = mac_address
        self.hostname = hostname
        self.inclusion_date = inclusion_date
        self.scantime = scantime
        self.open_ports = open_ports
        self.ip_network = ip_network

        # Parâmetros do SQLAlchemy
        self.network_ip = str(self.ip_address)
        if self.open_ports is not None:
            self.ports = ','.join(map(str, self.open_ports.keys()))
        else:
            self.ports = None
        if self.hostname is not None:
            if len(self.hostname.values()) > 0:
                self.name = self.hostname.values()[0]
            else:
                self.name = None
        else:
            self.name = None

    def __repr__(self):
        """
        Metodo que passa a lista de parametros da classe
        """
        return "<Host('%s, %s, %s, %s, %s, %s, %s')>" % (
            self.network_ip,
            self.mac_address,
            self.name,
            self.inclusion_date,
            self.scantime,
            self.ports,
            self.ip_network
        )
    
    
class HostArping(Base):
    """
    Entrada de ping do host
    """
    __tablename__ = 'host_arping'
    network_ip = Column(String(16), ForeignKey("host.network_ip"), nullable=False, primary_key=True)
    ping_date = Column(DateTime, nullable=False, default=arrow.now().datetime, primary_key=True)
    mac_address = Column(String(18), nullable=False)
    ip_network = Column(String(16), ForeignKey('network.ip_network'), nullable=True)
    
    def __init__(self,
                 network_ip,
                 ping_date,
                 mac_address=None,
                 ip_network=None):
        """
        Método construtor

        :param network_ip: Ip do dispositivo
        :param mac_address: MAC do dispositivo.
        :param ping_date: Data da entrada
        :return:
        """
        self.mac_address = mac_address
        self.network_ip = network_ip
        self.ping_date = ping_date
        self.ip_network = ip_network

    def __repr__(self):
        """
        Metodo que passa a lista de parametros da classe
        """
        return "<HostArping('%s, %s, %s, %s')>" % (
            self.mac_address,
            self.network_ip,
            self.ping_date,
            self.ip_network
        )

    def update_ping(self, session):
        """
        Insere uma nova entrada de ping
        :param session: Sessão do SQLAlchemy
        :return boolean: Verdadeiro ou Falso
        """
        # Descobre host
        host = session.query(Host).filter(
            Host.network_ip == self.network_ip
        ).first()

        retorno = False
        results = session.query(self.__table__).filter(
            and_(
                self.__table__.c.network_ip == self.network_ip,
                self.__table__.c.ping_date == self.ping_date
            )
        ).first()
        if results is None:
            # Insere uma nova entrada
            log.debug("Inserindo entrada de ping para o Host %s", self.network_ip)
            session.execute(
                self.__table__.insert().values(
                    mac_address=self.mac_address,
                    network_ip=self.network_ip,
                    ping_date=self.ping_date,
                    ip_network=host.ip_network
                )
            )
            retorno = True

        # Atualiza o MAC Address do Host
        if host.mac_address != self.mac_address:
            host = session.query(
                Host.__table__
            ).filter(
                Host.mac_address == self.mac_address
            ).first()
            if host is None:
                # Atualiza o MAC do IP atual
                log.debug("Atualizando MAC = %s para  host = %s", self.mac_address, self.network_ip)
                session.execute(
                    Host.__table__.update().values(
                        mac_address=self.mac_address
                    ).where(
                        Host.network_ip == self.network_ip
                    )
                )
            else:
                # Verifica se já existe o IP
                host_old = session.query(
                    Host.__table__
                ).filter(
                    Host.network_ip == self.network_ip
                ).first()

                if host_old is not None:
                    # Como o Ip ja existe, trata-se de uma mudança de MAC
                    # Regra: somente o ultimo IP ativo fica com o MAC. O anterior fica nulo
                    log.debug("Removendo MAC do host = %s", self.network_ip)
                    session.execute(
                        Host.__table__.update().values(
                            mac_address=None
                        ).where(
                            Host.network_ip == host_old.network_ip
                        )
                    )

        session.flush()
        return retorno

    def export_ping(self, server_url, session, dados=None):
        """
        Exporta contador da impressora para o Cocar

        :param server_url: URL do servidor do Cocar
        :param session: Sessão do banco de dados
        :param dados: Dados extras a serem enviados na requisição
        :return: Verdadeiro ou falso dependendo do sucesso
        """
        # Busca atributos da rede
        network = session.query(Network.__table__).filter(
            Network.__table__.c.ip_network == self.ip_network
        ).first()

        if network is None:
            name = None
            netmask = None
        else:
            name = network.name
            netmask = network.netmask

        export_url = server_url + self.mac_address
        counter_json = {
            'host': self.network_ip,
            'mac_address': self.mac_address,
            'ping_date': self.ping_date,
            'network_ip': self.network_ip,
            'local': name,
            'netmask': netmask
        }

        # Adiciona os dados se existirem
        if dados is not None:
            counter_json.update(dados)

        # Envia a requisição HTTP
        headers = {'content-type': 'application/json'}
        response = requests.post(
            export_url,
            data=json.dumps(counter_json),
            headers=headers
        )

        try:
            # Check if request has gone wrong
            response.raise_for_status()
        except HTTPError as e:
            # Something got wrong, raise error
            log.error("Erro ao exportar ping para o Host = %s\n%s", self.network_ip, response.text)
            log.error(e.message)
            return False

        if response.status_code == 200:
            log.info("ping para o Host = %s em %s "
                     "exportado com sucesso", self.network_ip, self.ping_date)

            # Remove o ping
            session.execute(
                HostArping.__table__.delete().where(
                    and_(
                        HostArping.__table__.c.mac_address == self.mac_address,
                        HostArping.__table__.c.ping_date == self.ping_date,
                        HostArping.__table__.c.network_ip == self.network_ip,
                    )
                )
            )
            session.flush()
            return True
        else:
            log.error("Erro na remoção da ping para o Host = %s. Status code = %s", self.network_ip, response.status)
            return False
