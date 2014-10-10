#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'
import logging
from .host import Host
from sqlalchemy import ForeignKey
from sqlalchemy.schema import Column
from sqlalchemy.types import String, Integer
from sqlalchemy import and_, insert, update

log = logging.getLogger()


class Printer(Host):
    """
    Classe que identifica uma impressora
    """
    __tablename__ = 'printer'
    network_ip = Column(String(16), ForeignKey("host.network_ip"), nullable=False, primary_key=True)
    model = Column(String)
    serial = Column(String(50))
    description = Column(String)

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


class PrinterCounter(Printer):
    """
    Classe que armazena o contador das impressoras
    """
    __tablename__ = 'printer_counter'
    network_ip = Column(String(16), ForeignKey("printer.network_ip"), nullable=False)
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
        results = session.query(self.__table__).filter(
            and_(
                self.__table__.c.counter == self.counter,
                self.__table__.c.counter_time == self.counter_time)
            ).first()
        print(results)
        if results is None:
            log.debug("Inserindo contador para impressora %s serial %s", self.network_ip, self.serial)
            session.execute(
                self.__table__.insert().values(
                    network_ip=self.network_ip,
                    counter=self.counter,
                    counter_time=self.counter_time
                )
            )
            return True

        session.execute(
            Printer.__table__.update().values(
                model=self.model,
                description=self.description,
                serial=self.serial
            ).where(
                Printer.__table__.c.network_ip == self.network_ip
            )
        )

        session.flush()
        return False