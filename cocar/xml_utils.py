#!/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'eduardo'

from lxml import etree
import model.computer
import model.printer
import model.host
from .session import SnmpSession


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
                    for osclass in osmatch.findall('osclass'):
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
                      timeout=None):
        if not self.hosts:
            raise AttributeError("It is necessary do load XML file first")

        # Ordena os sistemas operacionais por accuracy
        host = self.hosts[hostname]
        accuracy = int(0)
        if host.get('ports'):
            scantime = int(host.get('endtime')) - int(host.get('starttime'))
            #FIXME: Tem que encontrar uma forma melhor de identificar a impressora
            for value in ['9100']:
                if value in host['ports'].keys():
                    # Regra temporária!!! As impressoras serão identificadas pela porta 9100
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
                    # Tenta ler o contador para identificar a impressora
                    snmp_session = SnmpSession(
                        DestHost=hostname,
                        Timeout=timeout
                    )
                    status = snmp_session.printer_counter()
                    if status is not None:
                        # Se conseguir ler o contador, é impressora
                        printer = model.printer.Printer(
                            ip_address=hostname,
                            mac_address=host.get('mac'),
                            hostname=host.get('hostname'),
                            inclusion_date=host.get('endtime'),
                            scantime=scantime,
                            open_ports=host['ports'],
                        )
                        return printer
                    elif host.get('os'):
                        # Nesse caso já sei que é computador. Precisa identificar o OS
                        for os in host['os'].keys():
                            if int(host['os'][os]['accuracy']) > accuracy:
                                accuracy = int(host['os'][os]['accuracy'])
                                os_final = {
                                    'so_name': os,
                                    'accuracy': accuracy
                                }

                        scantime = int(host.get('endtime')) - int(host.get('starttime'))
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
                        # Desiste e retorna host genérico
                        host = model.host.Host(
                            ip_address=hostname,
                            mac_address=host.get('mac'),
                            hostname=host.get('hostname'),
                            inclusion_date=host.get('endtime'),
                            scantime=scantime,
                            open_ports=host['ports'],
                        )

                        return host
            else:
                host = model.host.Host(
                    ip_address=hostname,
                    mac_address=host.get('mac'),
                    hostname=host.get('hostname'),
                    inclusion_date=host.get('endtime'),
                    scantime=scantime,
                    open_ports=host['ports'],
                )

                return host
        elif host.get('os'):
            # Nesse caso já sei que é computador. Precisa identificar o OS
            for os in host['os'].keys():
                if int(host['os'][os]['accuracy']) > accuracy:
                    accuracy = int(host['os'][os]['accuracy'])
                    os_final = {
                        'so_name': os,
                        'accuracy': accuracy
                    }

            scantime = int(host.get('endtime')) - int(host.get('starttime'))
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
            # Não foi possível identificar. Só gera um host genérico
            scantime = int(host.get('endtime')) - int(host.get('starttime'))
            host = model.host.Host(
                ip_address=hostname,
                mac_address=host.get('mac'),
                hostname=host.get('hostname'),
                inclusion_date=host.get('endtime'),
                scantime=scantime,
                open_ports=host['ports'],
            )

            return host
