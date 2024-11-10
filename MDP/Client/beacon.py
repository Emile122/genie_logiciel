import functools
from scapy.packet import Packet
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt
from scapy.sendrecv import sniff

def ssid_filter(ssid: str, pkt: Packet) -> bool:
   
    if not pkt.haslayer(Dot11Beacon):
        return False
    layer = pkt.getlayer(Dot11Elt)
    while layer is not None and layer.ID != 0:
        layer = layer.getlayer(Dot11Elt, 2)
    if layer is not None:
        return layer.info.decode() == ssid
    return False

def print_packet(pkt):
    if pkt.haslayer(Dot11Beacon):
        ssid = pkt[Dot11Elt].info.decode('utf-8')
        print(f"Sniffed packet with SSID: {ssid}")

def capture(ssid: str, iface: str, timeout=3) -> Packet:

    results = sniff(
        lfilter=functools.partial(ssid_filter, ssid),
        iface=iface,
        timeout=timeout,
        prn=print_packet  # Specify the callback function to print each packet
    )
    return None if len(results) == 0 else results[0]

