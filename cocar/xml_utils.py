#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'
import logging
from lxml import etree
import model.computer
import model.printer
import model.host
import model.network_device
from .session import SnmpSession, ArpSession
from .coleta import Coleta

log = logging.getLogger()


class NmapXML(object):
    """
    Classe para realizar o parsing do arquivo XML do NMAP
    """
    def __init__(self,
                 xml):
        self.xml = xml
        self.hosts = dict()

    def parse_xml(self):
        """
        Parse XML file
        """
        infile = open(self.xml, 'r')

        for _, element in etree.iterparse(infile, events=('start', 'end'), tag='host'):
            addr_list = element.findall('address')

            # MAC e IP
            mac = None
            for addr in addr_list:
                if addr.get('addrtype') == 'ipv4':
                    host = addr.get('addr')
                elif addr.get('addrtype') == 'mac':
                    mac = addr.get('addr')

            # A chave do dicionário é o IP
            self.hosts[host] = dict()
            if 'mac' in locals():
                self.hosts[host]['mac'] = mac

            # Hostname
            self.hosts[host]['hostname'] = dict()
            for tag in element.find('hostnames').findall('hostname'):
                self.hosts[host]['hostname'][tag.get('type')] = tag.get('name')

            # Open ports
            ports = element.find('ports')
            self.hosts[host]['ports'] = dict()
            for port_xml in ports.findall('port'):
                if port_xml.find('service') is not None:
                    service = port_xml.find('service').get('name')
                else:
                    service = None

                # State pode ser vazio por alguma razão desconhecida
                if port_xml.find('state') is None:
                    state = None
                else:
                    state = port_xml.find('state').get('state')

                self.hosts[host]['ports'][port_xml.get('portid')] = {
                    'protocol': port_xml.get('protocol'),
                    'state': state,
                    'service': service,
                }

            # OS Matches
            os = element.find('os')
            if os is not None:
                self.hosts[host]['os'] = dict()
                for osmatch in os.findall('osmatch'):
                    self.hosts[host]['os'][osmatch.get('name')] = dict()
                    self.hosts[host]['os'][osmatch.get('name')]['accuracy'] = osmatch.get('accuracy')
                    for osclass in os.findall('osclass'):
                        self.hosts[host]['os'][osmatch.get('name')]['osclass'] = {
                            'type': osclass.get('type'),
                            'vendor': osclass.get('vendor'),
                            'osfamily': osclass.get('osfamily'),
                            'accuracy': osclass.get('accuracy'),
                            'cpe': osclass.findtext('cpe'),
                            'version': osmatch.get('name')
                        }

            # General attributes
            self.hosts[host]['starttime'] = element.get('starttime')
            self.hosts[host]['endtime'] = element.get('endtime')
            status = element.find('status')
            self.hosts[host]['state'] = status.get('state')

        return True

    def identify_host(self,
                      hostname,
                      timeout=10):
        if not self.hosts:
            raise AttributeError("It is necessary do load XML file first")

        # Ordena os sistemas operacionais por accuracy
        host = self.hosts[hostname]
        accuracy = int(0)

        # 1 - Primeiro checa se é impressora
        result = self.check_printer(hostname, timeout)
        if result is not None:
            log.debug("IDENTIFY - Host %s identified as Printer", hostname)
            return result

        # 2 - Verifica se é um ativo de rede
        result = self.check_device(hostname, timeout)
        if result is not None:
            log.debug("IDENTIFY - Host %s identified as Network Device", hostname)
            return result

        # 3 - Verifica se é computador
        result = self.check_computer(hostname, timeout)
        if result is not None:
            log.debug("IDENTIFY - Host %s identified as Computer", hostname)
            return result

        # 4 - Se não cair em nenhum desses, armazena como ativo genérico
        log.debug("IDENTIFY - Host %s not identified. Saving as generic Host", hostname)
        scantime = int(host.get('endtime')) - int(host.get('starttime'))
        result = model.host.Host(
            ip_address=hostname,
            mac_address=host.get('mac'),
            hostname=host.get('hostname'),
            inclusion_date=host.get('endtime'),
            scantime=scantime,
            open_ports=host.get('ports'),
        )

        return result

    def check_printer(self,
                      hostname,
                      timeout):
        """
        Verifica se o host é uma impressora
        :param hostname: Nome do host
        :param timeout: Tempo máximo para esperar resposta da requisição SNMP
        :return: Impressora identificada ou None
        """
        if not self.hosts:
            raise AttributeError("It is necessary do load XML file first")

        # Ordena os sistemas operacionais por accuracy
        host = self.hosts[hostname]

        # 1 - Primeiro busca se tem portas abertas
        scantime = int(host.get('endtime')) - int(host.get('starttime'))
        if host.get('ports'):
            # FIXME: Tem que encontrar uma forma melhor de identificar a impressora
            for value in ['9100']:
                if value in host['ports'].keys():
                    # 1.1 - Tenta ler a porta 9100
                    printer = model.printer.Printer(
                        ip_address=hostname,
                        mac_address=host.get('mac'),
                        hostname=host.get('hostname'),
                        inclusion_date=host.get('endtime'),
                        scantime=scantime,
                        open_ports=host['ports'],
                    )

                    return printer
                else:
                    # 1.2 - Tenta ler o contador para identificar a impressora
                    snmp_session = SnmpSession(
                        DestHost=hostname,
                        Timeout=timeout
                    )
                    status = snmp_session.printer_counter()
                    if status is not None:
                        # 1.2.1 - Se conseguir ler o contador, é impressora
                        printer = model.printer.Printer(
                            ip_address=hostname,
                            mac_address=host.get('mac'),
                            hostname=host.get('hostname'),
                            inclusion_date=host.get('endtime'),
                            scantime=scantime,
                            open_ports=host['ports'],
                        )
                        return printer
                    else:
                        # 1.2.2 - Não é impressora
                        return None
        else:
            # 2 - Tenta ler o contador para identificar a impressora
            snmp_session = SnmpSession(
                DestHost=hostname,
                Timeout=timeout
            )
            status = snmp_session.printer_counter()
            if status is not None:
                # 2.1  - Se conseguir ler o contador, é impressora
                printer = model.printer.Printer(
                    ip_address=hostname,
                    mac_address=host.get('mac'),
                    hostname=host.get('hostname'),
                    inclusion_date=host.get('endtime'),
                    scantime=scantime,
                    open_ports=host['ports'],
                )
                return printer
            else:
                # 2.2 - Não é impressora
                return None

    def check_device(self,
                     hostname,
                     timeout):
        """
        Busca um dispositivo de rede conhecido na coleta do Cocar

        :param hostname: Home do host
        :param timeout: Tempo máximo para esperar resposta SNMP
        :return: Dispositivo encontrado ou None
        """
        if not self.hosts:
            raise AttributeError("It is necessary do load XML file first")

        # Ordena os sistemas operacionais por accuracy
        host = self.hosts[hostname]

        # 1 - Primeiro busca se tem portas abertas
        scantime = int(host.get('endtime')) - int(host.get('starttime'))

        snmp_session = Coleta(
            DestHost=hostname,
            Timeout=timeout
        )
        service = snmp_session.identify_host()
        if service is None:
            # Não foi possível identificar o host através de SNMP. Retorna
            return None

        if service == "application":
            # Nesse caso é computador ou servidor de aplicação. Retorna
            return None

        device = model.network_device.NetworkDevice(
            ip_address=hostname,
            mac_address=host.get('mac'),
            hostname=host.get('hostname'),
            inclusion_date=host.get('endtime'),
            scantime=scantime,
            open_ports=host['ports'],
            service=service,
            community=snmp_session.Community
        )

        return device

    def check_computer(self,
                       hostname,
                       timeout):
        """
        Busca um computador

        :param hostname: Home do host
        :param timeout: Tempo máximo para esperar resposta SNMP
        :return: Computador encontrado ou None encontrado ou None
        """
        if not self.hosts:
            raise AttributeError("It is necessary do load XML file first")

        # Ordena os sistemas operacionais por accuracy
        host = self.hosts[hostname]
        accuracy = int(0)
        if host.get('os'):
            # Nesse caso já sei que é computador. Precisa identificar o OS
            os_final = dict()
            for os in host['os'].keys():
                if int(host['os'][os]['accuracy']) > accuracy:
                    accuracy = int(host['os'][os]['accuracy'])
                    os_final = {
                        'so_name': os,
                        'accuracy': accuracy,
                        'version': host['os'][os]['osclass'].get('version'),
                        'vendor': host['os'][os]['osclass'].get('vendor'),
                        'os_family': host['os'][os]['osclass'].get('os_family'),
                        'cpe': host['os'][os]['osclass'].get('cpe'),
                    }

            if not os_final:
                log.error("IDENTIFY - Não foi possível identificar o SO do host %s. Falha!", hostname)
                return None

            if host.get('mac') is None:
                # TODO: Achar uma maneira de descobrir a interface de rede ativa. Por enquanto está fixa em eth0
                arp = ArpSession(
                    host=hostname,
                    iface="eth0",
                    timeout=timeout
                )

                result = arp.scan()
                if result is None:
                    # Não posso retornar MAC vazio de jeito nenhum
                    log.error("IDENTIFY - MAC not found for host %s. Fail!", hostname)
                    return None

                host['mac'] = result

            scantime = int(host.get('endtime')) - int(host.get('starttime'))
            # print(os_final)
            computer = model.computer.Computer(
                ip_address=hostname,
                mac_address=host.get('mac'),
                hostname=host.get('hostname'),
                inclusion_date=host.get('endtime'),
                scantime=scantime,
                open_ports=host.get('ports'),
                so=os_final
            )

            return computer
        else:
            # Desiste
            return None
