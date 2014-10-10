#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'
from .. import Cocar
import os
import os.path
from ..model import Base

cocar = Cocar(environment='test')
test_dir = os.path.dirname(os.path.realpath(__file__))


def setup_package():
    """
    Setup test data for the package
    """
    Base.metadata.create_all(cocar.engine)
    pass


def teardown_package():
    """
    Remove test data
    """
    Base.metadata.drop_all(cocar.engine)
    pass