# -*- coding: utf-8 -*-

from config import *
import logging
from Client import Client


if __name__ == '__main__':

    if DEBUG_FLAG:
        logging.basicConfig(level=logging.DEBUG, format='%(levelname) -8s %(message)s')
        myClient = Client(DEBUG_USER, DEBUG_PASS)

    else:
        username = raw_input("Username:")
        password = raw_input("Password:")
        myClient = Client(username, password)


    if myClient.connect():
        myClient.process(block=False)
    else:
        logging.debug("Unable to connect")
