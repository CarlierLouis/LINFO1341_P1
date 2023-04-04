import pyshark
import matplotlib.pyplot as plt
plt.matplotlib.use('TkAgg')

path = 'Traces/SameWifi/SameWifi_Messages_Send_and_Recieve.pcapng'
capture = pyshark.FileCapture(path)

protocol_stats = {}
domainNameList = set()

# packet analysis based on detected protocols
for packet in capture:
    protocols = packet.frame_info.protocols.split(':')
    for protocol in protocols:
        if 'DNS' in packet:
            domainNameList.add(packet.dns.qry_name)
        if protocol in protocol_stats:
            protocol_stats[protocol] += 1
        else:
            protocol_stats[protocol] = 1

capture.close()

print(len(domainNameList))
print(sorted(domainNameList))

plt.bar(range(len(protocol_stats)), list(protocol_stats.values()), align='center')
plt.xticks(range(len(protocol_stats)), list(protocol_stats.keys()))
plt.xlabel('Protocoles')
plt.ylabel('Nombre de paquets')
imageName = './Graphs/' + path + '.png'
plt.savefig(imageName.replace('.pcapng', '').replace('Traces/DifferentWifi/', '').replace('Traces/SameWifi/', ''))
plt.show()
