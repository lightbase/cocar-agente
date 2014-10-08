#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'
import os

import ConfigParser
import logging
import logging.config

config = ConfigParser.ConfigParser()
here = os.path.abspath(os.path.dirname(__file__))
config_file = os.path.join(here, '../development.ini')
config.read(config_file)

# Logging
logging.config.fileConfig(config_file)

class Cocar(object):
    """
    Classe global com as configurações
    """

    def __init__(self):
        """
        Parâmetro construtor
        """
        cocar_data_dir = config.get('cocar', 'data_dir')

        if os.path.isdir(cocar_data_dir):
            self.cocar_data_dir = cocar_data_dir
        else:
            os.mkdir(cocar_data_dir)
            self.cocar_data_dir = cocar_data_dir