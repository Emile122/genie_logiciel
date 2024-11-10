import logging
from scapy.packet import Packet
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Auth
from scapy.sendrecv import srp1


def request(bssid: str, sta: str, iface: str, timeout=3) -> Packet:

    dot11 = Dot11(
        type='Management',
        subtype=11,
        addr1=bssid,
        addr2=sta,
        addr3=bssid
    )
    auth = Dot11Auth(
        algo='open',
        seqnum=1,
        status='success'
    )
    frame = RadioTap() / dot11 / auth
    logging.info(f'Authenticating to {bssid}:')
    logging.info(repr(frame))
    return srp1(frame, iface=iface, timeout=timeout)