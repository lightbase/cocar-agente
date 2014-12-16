"""Add foreign key

Revision ID: 51a6a93708f
Revises: 
Create Date: 2014-12-15 18:20:32.658762

"""

# revision identifiers, used by Alembic.
revision = '51a6a93708f'
down_revision = None
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa
from cocar.model import host, Base


def upgrade():
    network_ip = sa.Column('network_ip', sa.String(16), primary_key=True, nullable=False)
    network_ip2 = sa.Column('network_ip', sa.String(16), primary_key=True, nullable=False)
    mac_address = sa.Column('mac_address', sa.String(18))
    mac_address2 = sa.Column('mac_address', sa.String(18))
    name = sa.Column('name', sa.String)
    name2 = sa.Column('name', sa.String)
    inclusion_date = sa.Column('inclusion_date', sa.String(20))
    inclusion_date2 = sa.Column('inclusion_date', sa.String(20))
    scantime = sa.Column('scantime', sa.Integer)
    scantime2 = sa.Column('scantime', sa.Integer)
    ports = sa.Column('ports', sa.String)
    ports2 = sa.Column('ports', sa.String)
    ip_network = sa.Column('ip_network', sa.String(16), sa.ForeignKey('network.ip_network'), nullable=True)

    op.create_table(
        'host_bak',
        network_ip,
        mac_address,
        name,
        inclusion_date,
        scantime,
        ports
    )

    host_bak_table = sa.sql.table(
        'host_bak',
        network_ip,
        mac_address,
        name,
        inclusion_date,
        scantime,
        ports
    )

    host_table = sa.sql.table(
        'host',
        network_ip2,
        mac_address2,
        name2,
        inclusion_date2,
        scantime2,
        ports2,
        ip_network
    )

    # Copy all registers for new table
    connection = op.get_bind()

    result = connection.execute(
        "SELECT * FROM host"
    )

    saida = list()
    for linha in result:
        saida.append(dict(
            network_ip=linha[0],
            mac_address=linha[1],
            name=linha[2],
            inclusion_date=linha[3],
            scantime=linha[4],
            ports=linha[5]
        ))

    # Now insert all registers in new table
    op.bulk_insert(
        host_bak_table,
        saida
    )

    # Now drop old table and recreate
    op.drop_table(host.Host.__table__)
    host.Host.__table__.create(connection)

    # Finally add all registers back
    result = connection.execute(
        "SELECT * FROM host_bak"
    )

    saida = list()
    for linha in result:
        saida.append(dict(
            network_ip=linha[0],
            mac_address=linha[1],
            name=linha[2],
            inclusion_date=linha[3],
            scantime=linha[4],
            ports=linha[5]
        ))

    op.bulk_insert(
        host_table,
        saida
    )

    op.drop_table('host_bak')

    pass


def downgrade():
    pass