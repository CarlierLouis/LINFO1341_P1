import pyshark

cap = pyshark.FileCapture("Traces/DifferentWIfi/Call_Cam.pcapng")

print(cap[0])