#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'

from .host import Host


class Computer(Host):
    """
    Ativo de rede identificado como estação de trabalho
    """
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