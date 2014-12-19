#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'
import logging
import requests
import json
from requests.exceptions import HTTPError
from sqlalchemy.orm import aliased
from .host import Host
from sqlalchemy import ForeignKey
from sqlalchemy.schema import Column
from sqlalchemy.types import String, Integer, UnicodeText
from sqlalchemy import and_, insert, update
from .network import Network

log = logging.getLogger()


class Printer(Host):
    """
    Classe que identifica uma impressora
    """
    __tablename__ = 'printer'
    network_ip = Column(String(16), ForeignKey("host.network_ip"), nullable=False, primary_key=True)
    model = Column(UnicodeText)
    serial = Column(UnicodeText(50), primary_key=True, nullable=True)
    description = Column(UnicodeText)

    def __init__(self,
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
        self.model = model
        self.serial = serial
        self.description = description

    def export_printer(self, server_url, session):
        """
        Exporta todos os contadores para a impressora
        """
        #query = session.query(
        #    PrinterCounter
        #).filter(
        #    PrinterCounter.__table__.c.network_ip == self.network_ip
        #)

        stm = """SELECT host.network_ip as ip_address,
                    host.mac_address,
                    host.inclusion_date,
                    host.scantime,
                    printer.model,
                    printer.serial,
                    printer.description,
                    printer_counter.counter,
                    printer_counter.counter_time
                FROM host
                JOIN printer ON host.network_ip = printer.network_ip
                JOIN printer_counter ON printer.serial = printer_counter.serial
                WHERE printer_counter.serial = '%s'""" % self.serial

        counter_list = session.execute(stm, mapper=PrinterCounter).fetchall()

        for elm in counter_list:
            counter = PrinterCounter(**elm)
            print(counter)
            result = counter.export_counter(server_url, session)
            if result:
                log.info("Contador %s para a impressora %s exportado com sucesso", counter.counter, self.serial)
            else:
                log.error("Erro na remocao do contador %s para a impressora %s", counter.counter, self.serial)
                return False

        log.info("EXPORT DA IMPRESSORA %s FINALIZADO!!! %s CONTADORES EXPORTADOS!!!", self.serial, len(counter_list))
        return True


class PrinterCounter(Printer):
    """
    Classe que armazena o contador das impressoras
    """
    __tablename__ = 'printer_counter'
    serial = Column(UnicodeText(16), ForeignKey("printer.serial"), nullable=False, primary_key=True)
    counter = Column(Integer, nullable=False, primary_key=True)
    counter_time = Column(String(50), nullable=False, primary_key=True)

    def __init__(self,
                 counter,
                 counter_time,
                 *args,
                 **kwargs
                 ):
        super(PrinterCounter, self).__init__(*args, **kwargs)
        self.counter = counter
        self.counter_time = counter_time

    def update_counter(self, session):
        """
        Atualiza contador da impressora
        :param session: SQLAlchemy session
        :return boolean: True if inserted
        """
        retorno = False
        results = session.query(self.__table__).filter(
            and_(
                self.__table__.c.serial == self.serial,
                self.__table__.c.counter == self.counter,
                self.__table__.c.counter_time == self.counter_time
            )
        ).first()
        #print(results)
        if results is None:
            log.debug("Inserindo contador para impressora %s serial %s", self.network_ip, self.serial)
            session.execute(
                self.__table__.insert().values(
                    serial=self.serial,
                    counter=self.counter,
                    counter_time=self.counter_time
                )
            )
            retorno = True

        session.execute(
            Printer.__table__.update().values(
                network_ip=self.network_ip,
                model=self.model,
                description=self.description
            ).where(
                Printer.__table__.c.serial == self.serial
            )
        )

        session.flush()
        return retorno

    def export_counter(self, server_url, session):
        """
        Exporta contador da impressora para o Cocar

        :param server_url: URL do servidor do Cocar
        :param session: Sessão do banco de dados
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

        export_url = server_url + '/api/printer/' + self.serial
        counter_json = {
            'ip_address': self.network_ip,
            'model': self.model,
            'serial': self.serial,
            'description': self.description,
            'counter': self.counter,
            'counter_time': int(float(self.counter_time)),
            'local': name,
            'netmask': netmask
        }

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
        except HTTPError, e:
            # Something got wrong, raise error
            log.error("Erro na insercao do contador para a impressora %s\n%s", self.serial, response.text)
            log.error(e.message)
            return False

        if response.status_code == 200:
            log.info("Contador para a impressora %s com contador %s "
                     "exportado com sucesso", self.serial, self.counter)
            # Remove o contador
            session.execute(
                PrinterCounter.__table__.delete().where(
                    and_(
                        PrinterCounter.__table__.c.serial == self.serial,
                        PrinterCounter.__table__.c.counter == self.counter,
                        PrinterCounter.__table__.c.counter_time == self.counter_time,
                    )
                )
            )
            session.flush()
            return True
        else:
            log.error("Erro na remoção da impressora %s. Status code = %s", self.serial, response.status)
            return False
