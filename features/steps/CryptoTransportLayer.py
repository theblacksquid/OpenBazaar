#pylint: disable=function-redefined
from behave import given, then, when
from zmq.eventloop import ioloop

from node.db_store import Obdb
from node.setup_db import setup_db
from node.openbazaar_daemon import OpenBazaarContext
from node.transport import CryptoTransportLayer
from features.test_util import ip_address, nickname, get_db_path

port = 12345


def create_layers(context, num_layers):
    layers = []

    for i in range(num_layers):
        # dev_mode is True because otherwise the layer's ip is set to the
        # public ip of the node
        ob_ctx = OpenBazaarContext.create_default_instance()
        ob_ctx.dev_mode = True
        ob_ctx.server_ip = ip_address(i)
        ob_ctx.server_port = port
        db_path = get_db_path(i)
        setup_db(db_path, ob_ctx.disable_sqlite_crypt)
        layers.append(CryptoTransportLayer(ob_ctx, Obdb(db_path)))
    context.layers = layers


@given('{num_layers} layers')
def step_impl(context, num_layers):
    create_layers(context, int(num_layers))


@when('layer {i} connects to layer {j}')
def step_impl(context, i, j):
    i = int(i)
    j = int(j)
    iLayer = context.layers[i]
    jLayer = context.layers[j]

    jLayer.join_network([])

    def cb(msg):
        ioloop.IOLoop.current().stop()

    iLayer.join_network([ip_address(j)], callback=cb)
    ioloop.IOLoop.current().start()


@then('layer {i} is aware of layer {j}')
def step_impl(context, i, j):
    i = int(i)
    j = int(j)
    iLayer = context.layers[i]
    jLayer = context.layers[j]

    assert (ip_address(j), port, jLayer.guid, nickname(j)) in iLayer.dht.knownNodes

    # j is not necessarily in the database of i
    # db_peers = iLayer._db.selectEntries("peers")
    # assert(jLayer._uri in map(lambda x: x['uri'], known_peers))

    # j is not necessarily in activePeers of i
    # assert(jLayer._guid in map(lambda x: x._guid, iLayer.dht._activePeers))

    # j is not necessarily in peers of i
    # assert(jLayer._uri in iLayer._peers)
