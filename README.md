cocar-agente
============

Módulo agente coletor para o software Cocar

* Dependência: python-netsnmp

Para funcionar é necessário primeiro instalar o pacote da distribuição e só depois criar o virtualenv:

<pre>
virtualenv --system-site-packages -p /usr/bin/python2.7 cocar-agente
</pre>

Dependência de um módulo externo chamado pylanos

<pre>
cd /home/eduardo/srv/cocar-agente/src
cd cocar-agente/cocar
mkdir lib
cd lib
wget https://github.com/c0r3dump3d/pylanos/raw/master/PyLanOS.py
mv PyLanOS.py pylanos.py
</pre>