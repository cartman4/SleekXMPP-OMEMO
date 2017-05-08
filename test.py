# -*- coding: utf-8 -*-

from config import *
import logging
from Client import Client
import sys



if __name__ == '__main__':
    accounts = []

    if DEBUG_FLAG:
        logging.basicConfig(level=logging.DEBUG, format='%(levelname) -8s %(message)s')

    while True:
        print "-----------"
        print "# Main Menu #"
        print "-----------"
        print "[1]: Login/ Add Account"
        print "[2]: View own Fingerprint(s)"
        print "[3]: Join Groupchat (todo)"
        print "[4]: Send a OMEMO-Message"
        print "[5]: List my Accounts"
        print "[6]: Show Fingerprints from recipient"
        print "[0]: Exit"
        print "------------"

        userInput = raw_input("Choose a number:")

        if userInput == "0":
            sys.exit(0)


        elif userInput == "1":
            jid = raw_input("Your JID: ")
            passwd = raw_input("Your Password: ")
            newAccount = Client(jid, passwd)
            if newAccount.connect():
                accounts.append(newAccount)
                newAccount.process(block=False)
                print "Logged in! Please Wait while setting up OMEMO!"

            else:
                print "Unable to connect! Please try again later!"


        elif userInput == "2":
            if len(accounts) > 0:
                for acc in accounts:
                    print "==========================="
                    print acc.ownJID + ": " + acc['XEP_0384'].getOwnFingerprint()
                    print "DeviceID: " + str(acc['XEP_0384'].omemo.own_device_id)
                    print "==========================="
            else:
                print "No Accounts found!"


        elif userInput == "3":
            print "Sorry, not yet implemented!"


        elif userInput == "4":
            if len(accounts) >= 0:
                for i in range(len(accounts)):
                    print str(i) + ": " + accounts[i].ownJID
                choice = raw_input("Send from: ")
                if int(choice) <= len(accounts):
                    to_jid = raw_input("To:")
                    msg = raw_input("Message:")
                    accounts[int(choice)].sendOmemoMessage(to_jid, msg)
                else:
                    print "Wrong input!"


        elif userInput == "5":
            for acc in accounts:
                print acc.ownJID + "   DeviceID:" + str(acc['XEP_0384'].omemo.own_device_id)


        elif userInput == "6":
            if len(accounts) > 0:
                jid = raw_input("JID: ")
                for acc in accounts:
                    results = acc['XEP_0384'].getAllFingerprintsFor(jid)
                    for result in results.items():
                        print "==========================="
                        print "JabberID: %s" % jid
                        print "DeviceID: %s" % result[0]
                        print "Active: %s" % result[1]['active']
                        print "Fingerprint: %s" % result[1]['fingerprint']
                        print "==========================="
            else:
                print "No Accounts found!"



        else:
            print "Wrong input! Please try again!"
