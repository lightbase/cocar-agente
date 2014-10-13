#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'
from .. import Cocar
import os
import os.path
import logging
from urlparse import urlparse
from ..model import Base

cocar = Cocar(environment='test')
test_dir = os.path.dirname(os.path.realpath(__file__))
log = logging.getLogger()


def fake_urlopen(url):
    """
    A stub urlopen() implementation that load json responses from
    the filesystem.
    """
    # Map path from url to a file
    parsed_url = urlparse(url)
    resource_file = os.path.normpath('tests/fixtures/resources/printer%s' % parsed_url.path)
    # Must return a file-like object
    return open(resource_file, mode='rb')


def setup_package():
    """
    Setup test data for the package
    """
    log.debug("Diretório de dados do Cocar: %s", cocar.cocar_data_dir)
    test_dir = cocar.cocar_data_dir + "/tests"
    if not os.path.isdir(test_dir):
        log.info("Criando diretório de testes %s", test_dir)
        os.mkdir(test_dir)

    log.info(cocar.engine)
    Base.metadata.create_all(cocar.engine)
    pass


def teardown_package():
    """
    Remove test data
    """
    Base.metadata.drop_all(cocar.engine)
    pass