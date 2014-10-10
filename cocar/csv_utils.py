#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'
import csv
from .model.network import Network


class NetworkCSV(object):
    """
    Arquivo CSV das redes
    """
    def __init__(self,
                 csv_file):
        """
        Parse do arquivo CSV
        :param csv_file: Arquivo CSV para abrir
        """
        self.csv_file = csv_file

    def parse_csv(self):
        with open(self.csv_file, 'rb') as csvfile:
            saida = list()
            network_csv = csv.reader(csvfile, delimiter=';')
            for row in network_csv:
                network = Network(
                    network_ip=row[0],
                    netmask=row[1]
                )
                saida.append(network)

            return saida