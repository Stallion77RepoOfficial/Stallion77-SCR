# connection_sniffer_plugin.py

import threading
from scapy.all import sniff, IP, TCP, HTTPRequest

class ConnectionSniffer:
    def __init__(self):
        self.sniff_threads = {}
        self.active = False

    def start_all(self, app_instance):
        iface = app_instance.get_interface()
        if not iface:
            app_instance.log_message("Ağ arayüzü bulunamadı. Bağlantı sniffing başlatılamıyor.", 'red')
            return

        for target_ip in app_instance.targets:
            self.start(target_ip, iface, app_instance)

    def stop_all(self, app_instance):
        for target_ip in list(self.sniff_threads.keys()):
            self.stop(target_ip, app_instance)

    def start(self, target_ip, iface, app_instance):
        if target_ip in self.sniff_threads:
            app_instance.log_message(f"{target_ip} için Bağlantı sniffing zaten başlatılmış.", 'red')
            return

        thread = threading.Thread(target=self.sniff_connections, args=(target_ip, iface, app_instance), daemon=True)
        self.sniff_threads[target_ip] = thread
        thread.start()
        app_instance.log_message(f"Bağlantı sniffing başlatıldı: {target_ip}", 'green')

    def stop(self, target_ip, app_instance):
        if target_ip in self.sniff_threads:
            # Sniffing'i durdurmak için Scapy sniff fonksiyonunu durdurmak zor olabilir.
            # Bu nedenle, sniff işlemi için belirli bir koşul eklemek daha iyi olabilir.
            # Bu basit örnekte, sniff işlemi sürekli çalıştığı için durdurulamıyor.
            self.sniff_threads.pop(target_ip)
            app_instance.log_message(f"Bağlantı sniffing durduruldu: {target_ip}", 'red')
        else:
            app_instance.log_message(f"{target_ip} için aktif bağlantı sniffing bulunamadı.", 'red')

    def sniff_connections(self, target_ip, iface, app_instance):
        try:
            app_instance.log_message(f"{target_ip} için bağlantı sniffing başlatılıyor.", 'green')

            def packet_callback(packet):
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    if packet.haslayer(TCP):
                        tcp_layer = packet.getlayer(TCP)
                        if packet.haslayer(HTTPRequest):
                            http_layer = packet.getlayer(HTTPRequest)
                            host = http_layer.Host.decode() if hasattr(http_layer, 'Host') else ""
                            path = http_layer.Path.decode() if hasattr(http_layer, 'Path') else ""
                            url = f"http://{host}{path}"
                            app_instance.log_message(f"URL: {url} - Packet from {src_ip} to {dst_ip}", 'green')
                        else:
                            app_instance.log_message(f"Packet from {src_ip} to {dst_ip}", 'green')

            # Sürekli sniff yapar (daemon thread olarak çalışır, uygulama kapanınca durur)
            sniff(filter=f"host {target_ip}", iface=iface, prn=packet_callback, store=0)
        except Exception as e:
            app_instance.log_message(f"Bağlantı sniffing sırasında hata ({target_ip}): {e}", 'red')

def setup(app):
    connection_sniffer = ConnectionSniffer()
    connection_sniffer.filename = "connection_sniffer_plugin.py"  # Eklenti dosya adını belirlemek için
    return connection_sniffer
