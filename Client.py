from sleekxmpp import ClientXMPP
import logging
from config import *
from Plugins import XEP_0384 as OmemoModule
from sleekxmpp.xmlstream import ET, tostring
from sleekxmpp import Message
from Stanzas.helper import extractDevices

class Client(ClientXMPP):
    def __init__(self, ownJID, password):
        super(Client, self).__init__(ownJID, password)
        self.ownJID = ownJID
        self.password = password

        # Register Event Handlers
        self.add_event_handler('session_start', self.start)
        self.add_event_handler('pubsub_publish', self.pubsubEvent)
        # Register needed plugins
        self.register_plugin('xep_0030')
        self.register_plugin('XEP_0384', module=OmemoModule)
        self.register_plugin('xep_0059')
        self.register_plugin('xep_0060')




    """ We are ready to start

    """
    def start(self, event):
        # We are available now
        self.send_presence()
        # We need to subscribe to the Omemo Devicelist via PEP
        self['xep_0060'].subscribe(None, NS_DEVICELIST)
        # Prepare OmemoSupport
        self['XEP_0384'].prepareOmemoSupport(self.ownJID)
        self.sendOmemoMessage(DEBUG_RECIPIENTJID, "hello")




    """ Pubsub: We recieved a Pubsub Event message

        Parameters:
        ------------
        msg:    Message with our PubsubEvent payload
    """
    def pubsubEvent(self, msg):
        devicelist = extractDevices(msg['pubsub_event']['items']['item']['payload'])
        if self.ownJID == msg['from']:
            self['XEP_0384'].omemo.set_own_devices(devicelist)
        else:
            self['XEP_0384'].omemo.set_devices(devicelist)



    """ Send an OmemoMessage

        Parameters:
        -------------
        toJID   :   String
                    jabber id of the recipient
        msg     :   String
                    Text of the message
    """
    def sendOmemoMessage(self, to_jid, msg):
        # Encrypt the message and get the msg dict
        self['XEP_0384'].sendOmemoMessage(self.ownJID, to_jid, msg)
