import os
import sys

from scapy.layers.dot11 import Dot11Beacon
from scapy.sendrecv import sniff

timeOut = 10000
aps_dict = {}
evil_aps = {}


def scanEvilAP(pkt):
    if pkt.haslayer(Dot11Beacon):  # check if the pkt is dot11
        if pkt.type == 0 and pkt.subtype == 8:  # check if ( type 0-Management , 8 - Beacon)
            if not (pkt.info.decode("utf-8") in aps_dict):  # decode("utf-8") - cast to String
                #network_stats()['crypto'] = [OPN,WEP,WPA,WPA2]
                if not('OPN' in pkt[Dot11Beacon].network_stats()['crypto']): # add only the secured ap
                    aps_dict[pkt.info.decode("utf-8")] = pkt.addr3
            elif (aps_dict[pkt.info.decode("utf-8")] != pkt.addr3):  # check if the MAC not equals to the ap's mac in the dict
                if 'OPN' in pkt[Dot11Beacon].network_stats()['crypto']:
                    if not (pkt.info.decode("utf-8") in evil_aps):
                        print("%s" % (pkt.info.decode("utf-8")))
                        evil_aps[pkt.info.decode("utf-8")] = pkt.info.decode("utf-8")
            # else: pass
        else:
            pass
    else:
        pass


def makeMonitorMode(interfaceName):
    print('Change %s to monitor mode' % (interfaceName))
    os.system('sudo ifconfig %s down' % (interfaceName))
    os.system('sudo iwconfig %s mode monitor' % (interfaceName))
    os.system('sudo ifconfig %s up' % (interfaceName))


def main():
    interfaceName = sys.argv[1]
    makeMonitorMode(interfaceName)
    print("Check evil AP's....\n")
    print("You should to be careful from :")
    sniff(prn=scanEvilAP, iface=interfaceName, count=timeOut)  # iface - interface to sniff , prn - function


if _name_ == '_main_':
    main()