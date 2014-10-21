Instalação
============

Módulo agente coletor para o software Cocar

* Dependência: python-netsnmp

Para funcionar é necessário primeiro instalar o pacote da distribuição e só depois criar o virtualenv:

<pre>
virtualenv --system-site-packages -p /usr/bin/python2.7 cocar-agente
</pre>


Operação
================

Descrição dos principais comandos de operação

* Varredura contínua de rede

<pre>
/srv/cocar-agente/bin/paster scan continous_scan
</pre>

* Leitura e export do contador das impressoras

<pre>
/srv/cocar-agente/bin/paster scan printer_scan -t 10000000
</pre>

* Coleta de MAC address que não foi inicialmente identificado

<pre>
/srv/cocar-agente/bin/paster scan scan_mac_all -a eth0 -t 10
</pre>