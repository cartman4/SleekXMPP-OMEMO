# -*- coding: utf-8 -*-
from sleekxmpp.xmlstream import ElementBase, ET
from sleekxmpp import Message
from config import *
import base64

class OmemoMessage(ElementBase):
    namespace = NS_OMEMO
    name = 'encrypted'
    plugin_attrib = 'OmemoMessage'
    interfaces = set(('header', 'key', 'payload', 'iv'))
    sub_interfaces = interfaces



    """ Extracting the IV off the header

        Return
        -------
        iv    :     bytes
                    The IV from the Omemo Message

    """
    def getIv(self):
        xml = self.xml.find('{%s}header' % self.namespace)
        for elem in xml:
            if elem.tag == '{%s}iv' % self.namespace:
                return base64.b64decode(elem.text)
        return Null




    """ Extracting the Sender device ID (sid) out of the header

        Return
        -------
        senderID    :   int
                        The senders device id

    """
    def getSid(self):
        xml = self.xml.find('{%s}header' % self.namespace)
        return int(xml.attrib['sid'])




    """
        Extracting keys and the Reciepients device ID (rid)
        out of <key> Tag

        Return
        -------
        keys : dict{
            rid : base64 decoded key value,
        }
    """
    def getKey(self):
        xml = self.xml.find('{%s}header' % self.namespace)
        keys = {}
        for elem in xml:
            if elem.tag == "{%s}key" % self.namespace:
                rid = int(elem.attrib['rid'])
                keys[rid] = base64.b64decode(elem.text)
        return keys
