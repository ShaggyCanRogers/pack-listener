import scapy.all as scapy
from scapy_http import http

#paketleri ilk önce dinlicez koklucaz sniff ile
#store false ile dinlenen paketleri kaydetmicek
def listen_packet(interface):
    scapy.sniff(iface=interface,store=False,prn=analyze_packet)

    #prn paketler geldikçe ben bu paketeri hangi func a yollıyım diye soruyor

def analyze_packet(packet):
    #packet.show()  #paketleri görebilmek için
    #http nin içinde http request var onun da içinde row var ve onun da içinde load kısmı var biz load a erişmeye çalışacaz
    if packet.haslayer(http.HTTPRequest):       #httprequest diye bir katman varsa içine gir
        if packet.haslayer(scapy.Raw):          #raw diye bir katman varsa onun içine gir
            print(scapy[scapy.Raw].load)        # scapy i liste gibi davranıp scapy.raw katmanına erişim oradaki lo  kısmını erişecek


listen_packet("eth0")

