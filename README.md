Instalação
============

Módulo agente coletor para o software Cocar

* Dependência: python-netsnmp

Instalação Debian e Ubuntu
---------------------------------

* Instala o pacote python-netsnmp

<pre>
apt-get install python-netsnmp
</pre>

Instalação RedHat e CentOS
------------------------------

**Importante**: não adianta instalar o pacote netsnmp da distribuição no RedHat/CentOS 6 ou menor. É preciso baixar o módulo do site e compilar.

* Escolha a versão no seguinte endereço: http://www.net-snmp.org/download.html
* Baixe para o diretório de compilação

<pre>
cd /usr/local/src
wget http://downloads.sourceforge.net/project/net-snmp/net-snmp/5.7.3/net-snmp-5.7.3.tar.gz?r=&ts=1423067645&use_mirror=ufpr
tar -xzvf net-snmp-5.7.3.tar.gz
</pre>

* Instale o repositório software collections do Red Hat e baixe o Python 2.7

<pre>
yum install centos-release-SCL make
yum install python27-python-devel
yum install perl-CPAN
yum install gcc
yum install libxml2-devel libxslt-devel nmap
</pre>

* Agora habilite o Python recentement instalado e setuptools

<pre>
source /opt/rh/python27/enable
wget https://bootstrap.pypa.io/ez_setup.py -O - | /opt/rh/python27/root/usr/bin/python
</pre>

* Finalmente compile fornecendo os diretórios do Python recentemente instalado

<pre>
cd /usr/local/src/net-snmp-5.7.3
./configure --prefix=/opt/rh/python27/root/usr/local --exec-prefix=/opt/rh/python27/root/usr/local --with-python-modules
make
make install
</pre>

* Adicione às configurações das variáveis de ambiente o path das libs que acabou de baixar

<pre>
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/rh/python27/root/usr/local/lib
echo -e "source /opt/rh/python27/enable\nexport LD_LIBRARY_PATH=\$LD_LIBRARY_PATH:/opt/rh/python27/root/usr/local/lib" >> ~/.bashrc
</pre>

* O último passo é verificar se a instalação ocorreu como deveria

<pre>
python

Python 2.7.5 (default, Jul 10 2014, 16:10:08) 
[GCC 4.4.7 20120313 (Red Hat 4.4.7-4)] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import netsnmp
>>> 
</pre>

Se não der nenhum erro tudo instalou sem problemas

Configura ambiente virtual
------------------------------

Só vai funcionar se utilizar o netsnmp do SO

<pre>
mkdir /usr/local/lightbase
easy_install virtualenv
cd /usr/local/lightbase
virtualenv --system-site-packages -p python2.7 cocar-agente
</pre>

* Baixa os fontes

<pre>
cd /usr/local/lightbase
mkdir src
# Escolha seu release
wget https://github.com/lightbase/cocar-agente/archive/1.0.tar.gz
tar -xzvf 1.0.tar.gz
cd cocar-agente-1.0
python setup.py develop
</pre>

Configuração
======================

* Crie diretório de dados

<pre>
mkdir /usr/local/lightbase/cocar-data
</pre>

* Crie o arquivo de configuração

<pre>
cd /usr/local/lightbase/src/cocar-agente-1.0
cp development.ini-dist production.ini
vim production.ini
</pre>

* Preencha as configurações

<pre>
[alembic]
# path to migration scripts
script_location = alembic
sqlalchemy.url = sqlite:////usr/local/lightbase/cocar-agente/cocar_data/cocar.db

[cocar]
data_dir = /usr/local/lightbase/cocar-agente/cocar_data
networks_csv = /usr/local/lightbase/cocar-agente/cocar_data/networks.csv
processes = 4
server_url = http://localhost/cocar  # Essa deve ser a URL do Cocar

[sqlalchemy]
url = sqlite:////usr/local/lightbase/cocar-agente/cocar_data/cocar.db
</pre>

Operação
================

Descrição dos principais comandos de operação

* Varredura contínua de rede

<pre>
/usr/local/lightbase/cocar-agente/bin/paster scan continous_scan
</pre>

* Leitura e export do contador das impressoras

<pre>
/usr/local/lightbase/cocar-agente/bin/paster scan printer_scan -t 10000000
</pre>

* Coleta de MAC address que não foi inicialmente identificado

<pre>
/usr/local/lightbase/cocar-agente/bin/paster scan scan_mac_all -a eth0 -t 10
</pre>

