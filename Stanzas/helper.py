import base64
from sleekxmpp import Message
from sleekxmpp.xmlstream import tostring
from config import *

""" Make a valid message stanza from the msg_dict

    Parameters
    -------------
    ownJID      :   string
                    Own jabber id
    msg_dict    :   dict{
                        'sid'   :   int: Device id from sender
                        'keys'  :   dict: {
                                        'rid': Reciepient Device id
                                        (key (bytes), isPreKey(bool))
                                    }
                        'jid'   :   string: recipient jabber id
                        'iv'    :   b64 encoded IV
                        'payload':  b64 encoded payload
                    }
                    Created from OmemoState:create_msg
    Return
    --------
    omemoMsg    :   string
                    XML String with OmemoMessage
"""
def omemoMsgDictToStanza(ownJID, msg_dict, msgType="chat"):
    # We need the Original message Stanza to build
    # our OMEMO Message XML
    skelMsg = Message()
    skelMsg['from'] = ownJID
    skelMsg['to']   = msg_dict['jid']
    skelMsg['body'] = "{{REPLACEME}}"
    skelMsg['type'] = msgType

    # Bit ugly TODO: Search better way to create OmemoMessageStanza
    omemoXML = "<encrypted xmlns='%s'>" % NS_OMEMO
    omemoXML += "<header sid='%s'>" % msg_dict['sid']
    for key in msg_dict['keys'].items():
        if key[1][1] == "true":
            omemoXML += "<key rid='%s' prekey='true'>%s</key>" % (key[0],
                                                    base64.b64encode(key[1][0])
                                                    )
        else:
            omemoXML += "<key rid='%s'>%s</key>" % (key[0],
                                                    base64.b64encode(key[1][0])
                                                    )
    omemoXML += "<iv>%s</iv>" % base64.b64encode(msg_dict['iv'])
    omemoXML += "</header>"
    omemoXML += "<payload>%s</payload>" % base64.b64encode(msg_dict['payload'])
    omemoXML += "</encrypted>"
    omemoXML += "<encryption xmlns='urn:xmpp:eme:0' namespace='%s' name='OMEMO' />" % NS_OMEMO
    omemoXML += "<store xmlns='urn:xmpp:hints' />"

    # We need the Skeleton XML as String
    omemoMsg = tostring(skelMsg.xml)
    omemoMsg = omemoMsg.replace("<body>{{REPLACEME}}</body>", omemoXML)
    return omemoMsg





""" Extract Device ID from devicelist Node

    Parameters
    ------------
    nodeData    :   ElementTree
                    XML with devicelist

    Return
    ---------
    devicelist  :   int[]
                    List with device ids
"""
def extractDevices(nodeData):
    if nodeData is not None:
        devicelist = []
        for device in nodeData:
            if device.tag == "{%s}device" % NS_OMEMO:
                devicelist.append(int(device.attrib['id']))
        return devicelist
    else:
        return
