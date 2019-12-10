import playground
from .protocol import CRAPClientFactory, CRAPServerFactory

CRAPConnector = playground.Connector(protocolStack=(CRAPClientFactory(),CRAPServerFactory()))
playground.setConnector("lzy_crap", CRAPConnector)

