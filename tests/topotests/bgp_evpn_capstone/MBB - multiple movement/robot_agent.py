"""Keep Scapy ready inside one robot namespace and send one learning ARP on demand."""

import json
import sys
import time

from scapy.all import ARP, Ether, sendp

mac, ip = sys.argv[1:]
packet = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
    op=1, hwsrc=mac, psrc=ip, pdst="45.0.0.1"
)
print(json.dumps({"ready": True}), flush=True)
for command in sys.stdin:
    if command.strip() == "quit":
        break
    started = time.time()
    try:
        sendp(packet, iface="bond0", verbose=False)
        result = {"sent": True, "send_start": started, "send_end": time.time()}
    except Exception as exc:
        result = {"sent": False, "error": str(exc), "send_start": started,
                  "send_end": time.time()}
    print(json.dumps(result), flush=True)
