#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'
import logging
import session
import cisco
import netsnmp

log = logging.getLogger()


class Coleta(session.SnmpSession):
    """
    Coleta SNMP
    """
    def __init__(self, *args, **kwargs):
        """
        Método construtor

        :param args:
        :param kwargs:
        :return:
        """
        super(Coleta, self).__init__(*args, **kwargs)

        # Coletas SNMP para ativos de rede
        self.sys_up_time = ['.1.3.6.1.2.1.1.3.0']  # Uptime
        self.snmp_hostname = ['.1.3.6.1.2.1.1.5.0']  # Hostname
        self.version = [".1.3.6.1.2.1.1.1.0"]  # Descriçao completa, incluindo tipo de hardware e rede
        self.location = [".1.3.6.1.2.1.1.6.0"]  # Localização
        self.contact = [".1.3.6.1.2.1.1.4.0"]  # Contato do resposável pelo equipamento
        self.avg_busy1 = [".1.3.6.1.4.1.9.2.1.57.0"]  # Load Average último minuto
        self.avg_busy5 = [".1.3.6.1.4.1.9.2.1.58.0"]  # Load average últimos 5 minutos
        self.memory = [".1.3.6.1.4.1.9.3.6.6.0"]  # Utilização de CPU
        self.services = [".1.3.6.1.2.1.1.7.0"]  # Serviços oferecidos
        self.ip_forwarding = ['.1.3.6.1.2.1.4.1']  # Retorna 1 se estiver fazendo IP Forwarding (router)
        self.bridge = ['.1.3.6.1.2.1.17']  # Retorna 1 se estiver fazendo bridge (switch)

        # Atributos genéricos importantes
        self.if_phys_address = [".1.3.6.1.2.1.2.2.1.6"]  # MAC Address

        # Atributos específicos para ativos CISCO
        self.chassis = ['.1.3.6.1.4.1.9.3.6.1.0']  # Chassis para a função get_chassis
        self.why_reload = [".1.3.6.1.4.1.9.2.1.2.0"]  # Motivo do último reinício
        self.sys_config_name = [".1.3.6.1.4.1.9.2.1.73.0"]  # CISCO - Nome da imagem de boot do dipositivo
        self.ts_lines = [".1.3.6.1.4.1.9.2.9.1.0"]  # Número de linhas do terminal
        self.cm_system_installed_modem = [".1.3.6.1.4.1.9.9.47.1.1.1.0"]  # Modems instalados em ativos CISCO
        self.cm_system_modems_in_use = [".1.3.6.1.4.1.9.9.47.1.1.6.0"]  # Modems em uso nos ativos CISCO
        self.cm_system_modems_dead = [".1.3.6.1.4.1.9.9.47.1.1.10.0"]  # Modems falhando em ativos CISCO

        # Interfaces de rede
        self.if_index = [".1.3.6.1.2.1.2.2.1.1"]
        self.if_descr = [".1.3.6.1.2.1.2.2.1.2"]
        self.description = [".1.3.6.1.2.1.31.1.1.1.18"]
        self.ip = [".1.3.6.1.2.1.4.20.1.1"]
        self.ip_order = [".1.3.6.1.2.1.4.20.1.2"]
        self.if_admin_status = [".1.3.6.1.2.1.2.2.1.7"]
        self.if_oper_status = [".1.3.6.1.2.1.2.2.1.8"]
        self.last_change = [".1.3.6.1.2.1.2.2.1.9"]
        self.if_mac = [".1.3.6.1.2.1.2.2.1.6"]

        # Definições genéricas de opções válidas no escopo do objeto
        self.service_options = {
            1: "repeater",
            2: "bridge",
            4: "router",
            6: "switch",
            8: "gateway",
            16: "session",
            32: "terminal",
            64: "application"
        }

        self.chassis_options = cisco.chassis_options
        self.card_type = cisco.card_type

    def identify_host(self):
        """
        Identifica o ativo de rede de acordo com o tipo de serviço fornecido.
        Parâmetro sysServices do SNMP.

        Fonte: http://www.alvestrand.no/objectid/1.3.6.1.2.1.1.7.html
        """
        service = None
        for elm in self.services:
            if service is not None:
                break
            self.var = netsnmp.Varbind(elm, iid=None)
            status = self.query()
            if status.query is not None:
                for response in status.query:
                    if response is not None:
                        service = response
                        # Só preciso de uma resposta
                        break

        if service is None:
            return None

        # Tudo o que for maior que 64 representa um computador que não será coletado via SNMP
        if int(service) > 64:
            return "application"

        return self.service_options.get(int(service))

    def get_chassis(self):
        """
        The serial number of the chassis. This MIB object will return the chassis serial number for any
        chassis that either a numeric or an alphanumeric serial number is being used.

        Fonte: http://tools.cisco.com/Support/SNMP/do/BrowseOID.do?local=en&translate=Translate&objectInput=1.3.6.1.4.1.9.5.1.2.19

        Número de série do ativo de rede

        :return: String que descreve o tipo de ativo
        """
        response = self.get_snmp_attribute("chassis")
        if response is not None:
            # Busca elemento no dicionário de respostas
            return self.chassis_options.get(response)
        else:
            # Retorna vazio para atributo não encontrado
            return None

    def get_sys_uptime(self):
        """
        Retorna o uptime do sistema
        """
        return self.get_snmp_attribute("sys_up_time")

    def get_hostname(self):
        """
        Hostname do Sistema
        """
        return self.get_snmp_attribute("snmp_hostname")

    def get_general(self, cisco=False):
        """
        Coleta geral do Host

        :param cisco: Habilitar coleta cisco?
        """
        oids = self.services +\
            self.sys_up_time +\
            self.version +\
            self.location +\
            self.contact +\
            self.avg_busy1 +\
            self.avg_busy5 +\
            self.memory +\
            self.ip_forwarding +\
            self.bridge

        if cisco:
            oids += self.chassis +\
                self.why_reload +\
                self.sys_config_name +\
                self.ts_lines +\
                self.cm_system_installed_modem +\
                self.cm_system_modems_dead +\
                self.cm_system_modems_in_use

        self.var_list = oids

        # Run the SNMP query
        result = self.getbulk()

        # Resultado:
        # (
        # '72', '1221085', None, 'Linux se-128156 3.13.0-65-generic #106-Ubuntu SMP Fri Oct 2 22:08:27 UTC 2015 x86_64',
        # 'Sitting on the Dock of the Bay', 'Me <me@example.org>', None, None, None, None, None
        # )
        print(result.query)
        if result.query is None:
            return None

        saida = result.query
        saida.append(self.DestHost)
        saida.append(self.Community)

        return result