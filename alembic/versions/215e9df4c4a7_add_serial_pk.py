"""Adiciona serial como chave da impressora

Revision ID: 215e9df4c4a7
Revises: 51a6a93708f
Create Date: 2014-12-17 22:34:20.998218

"""

# revision identifiers, used by Alembic.
revision = '215e9df4c4a7'
down_revision = '51a6a93708f'
branch_labels = None
depends_on = None

from alembic import op
from cocar.model import printer
import sqlalchemy as sa
import logging

log = logging.getLogger()


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    network_ip = sa.Column('network_ip', sa.String(16))
    network_ip2 = sa.Column('network_ip', sa.String(16))
    network_ip_new = sa.Column('network_ip', sa.String(16), sa.ForeignKey("host.network_ip"), nullable=False, primary_key=True)
    model = sa.Column('model', sa.String)
    model_new = sa.Column('model', sa.String)
    serial_new = sa.Column('serial', sa.String(50), primary_key=True, nullable=True)
    serial_new2 = sa.Column('serial', sa.String(50), primary_key=True, nullable=True)
    serial_new3 = sa.Column('serial', sa.String(50), primary_key=True, nullable=True)
    serial = sa.Column('serial', sa.String(50))
    description = sa.Column('description', sa.String)
    description_new = sa.Column('description', sa.String)
    counter = sa.Column('counter', sa.Integer, nullable=False, primary_key=True)
    counter_new = sa.Column('counter', sa.Integer, nullable=False, primary_key=True)
    counter_time = sa.Column('counter_time', sa.String(50), nullable=False, primary_key=True)
    counter_time_new = sa.Column('counter_time', sa.String(50), nullable=False, primary_key=True)

    op.create_table(
        'printer_bak',
        network_ip,
        serial_new3,
        model,
        description
    )

    printer_bak_table = sa.sql.table(
        'printer_bak',
        network_ip,
        serial_new3,
        model,
        description
    )

    printer_table = sa.sql.table(
        'printer',
        network_ip_new,
        serial_new,
        model_new,
        description_new
    )

    op.create_table(
        'printer_counter_bak',
        network_ip2,
        serial,
        counter,
        counter_time
    )

    printer_counter_bak_table = sa.sql.table(
        'printer_counter_bak',
        network_ip2,
        serial,
        counter,
        counter_time
    )

    printer_counter_table = sa.sql.table(
        'printer_counter',
        serial_new2,
        counter_new,
        counter_time_new
    )

    # Copy all registers for new table
    connection = op.get_bind()

    # Backup printer
    result = connection.execute(
        """SELECT network_ip,
                  model,
                  serial,
                  description
           FROM printer"""
    )

    for linha in result:
        p = connection.execute(
            printer_bak_table.select().where(
                printer_bak_table.c.serial == linha[2]
            )
        )

        found = p.first()

        if found is None and linha[2] is not None:
            connection.execute(
                printer_bak_table.insert().values(
                    network_ip=linha[0],
                    model=linha[1],
                    serial=linha[2],
                    description=linha[3]
                )
            )
        else:
            log.error("Entrada de serial repetida: %s", linha[2])
            continue

    # Backup printer_counter
    result = connection.execute(
        """SELECT c.network_ip,
                  p.serial,
                  c.counter,
                  c.counter_time
           FROM printer_counter c
           INNER JOIN printer p ON c.network_ip = p.network_ip"""
    )

    saida = list()
    for linha in result:
        saida.append(dict(
            network_ip=linha[0],
            serial=linha[1],
            counter=linha[2],
            counter_time=linha[3]
        ))

    # Now insert all registers in new table
    op.bulk_insert(
        printer_counter_bak_table,
        saida
    )

    # Drop and recreate tables
    op.drop_table(printer.Printer.__table__)
    printer.Printer.__table__.create(connection)

    op.drop_table(printer.PrinterCounter.__table__)
    printer.PrinterCounter.__table__.create(connection)

    # Finally insert registers back
    result = connection.execute(
        """SELECT DISTINCT network_ip,
                  model,
                  serial,
                  description
           FROM printer_bak"""
    )

    for linha in result:
        log.debug("Inserindo impressora com serial %s e IP %s", linha[2], linha[0]);
        p = connection.execute(
            printer_table.select().where(
                sa.and_(
                    printer_table.c.serial == linha[2],
                    printer_table.c.network_ip == linha[0]
                )
            )
        )

        found = p.first()

        if found is None:
            connection.execute(
                printer_table.insert().values(
                    network_ip=linha[0],
                    model=linha[1],
                    serial=linha[2],
                    description=linha[3]
                )
            )

    # Insert back printer counter
    result = connection.execute(
        """SELECT network_ip,
                  serial,
                  counter,
                  counter_time
           FROM printer_counter_bak"""
    )

    for linha in result:
        c = connection.execute(
            printer_counter_table.select().where(
                sa.and_(
                    printer_counter_table.c.serial == linha[1],
                    printer_counter_table.c.counter == linha[2],
                    printer_counter_table.c.counter_time == linha[3]
                )
            )
        )

        found = c.first()

        if found is None and linha[1] is not None:
            connection.execute(
                printer_counter_table.insert().values(
                    serial=linha[1],
                    counter=linha[2],
                    counter_time=linha[3]
                )
            )
        else:
            log.error("Entrada repetida para a impressora %s", linha[1])
            continue

    op.drop_table('printer_bak')
    op.drop_table('printer_counter_bak')

    pass


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    pass
    ### end Alembic commands ###