#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'
import os

import ConfigParser
import logging
import logging.config
from sqlalchemy.engine import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker


def load_config(environment='development'):
    config = ConfigParser.ConfigParser()
    here = os.path.abspath(os.path.dirname(__file__))
    config_file = os.path.join(here, '../' + environment + '.ini')
    config.read(config_file)

    # Logging
    logging.config.fileConfig(config_file)

    return config


class Cocar(object):
    """
    Classe global com as configurações
    """

    def __init__(self,
                 environment='development'
                 ):
        """
        Parâmetro construtor
        """
        self.config = load_config(environment)
        cocar_data_dir = self.config.get('cocar', 'data_dir')
        if environment == 'test':
            # Add test do dir to make sure we protect production data
            cocar_data_dir += "/tests"

        if not os.path.isdir(cocar_data_dir):
            os.mkdir(cocar_data_dir)

        self.cocar_data_dir = cocar_data_dir

        # SQLAlchemy
        sqlalchemy_url = self.config.get('sqlalchemy', 'url')
        self.engine = create_engine(sqlalchemy_url, echo=True)
        self.Session = scoped_session(
            sessionmaker(bind=self.engine,
                         autocommit=True
            )
        )