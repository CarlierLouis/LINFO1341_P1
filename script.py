import pyshark
import matplotlib.pyplot as plt
plt.matplotlib.use('TkAgg')

path = 'Traces/DifferentWIfi/Messages_Send_and_Recieve.pcapng'
capture = pyshark.FileCapture(path)

protocol_stats = {}
domainNameList = set()

# packet analysis based on detected protocols
for packet in capture:
    protocols = packet.frame_info.protocols.split(':')
    for protocol in protocols:
        if 'DNS' in packet:
            domainNameList.add(packet.dns.qry_name)

for packet in capture:
    protocol = packet.transport_layer
    if protocol is None:
        protocol = packet.highest_layer
    if protocol in protocol_stats:
        protocol_stats[protocol] += 1
    else:
        protocol_stats[protocol] = 1

capture.close()

print(domainNameList)

plt.bar(range(len(protocol_stats)), list(protocol_stats.values()), align='center')
plt.xticks(range(len(protocol_stats)), list(protocol_stats.keys()))
plt.xlabel('Protocoles')
plt.ylabel('Nombre de paquets')
imageName = './Graphs/' + path + '.png'
plt.savefig(imageName.replace('.pcapng', '').replace('Traces/DifferentWIfi/', '').replace('Traces/SameWifi/', ''))
plt.show()
