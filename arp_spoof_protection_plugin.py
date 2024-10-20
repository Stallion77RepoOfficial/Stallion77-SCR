import threading
import time
from scapy.all import ARP, sniff, Ether, srp, send

class ARPSpoofProtection:
    def __init__(self):
        self.threads = {}  # Aktif dinleme thread'lerini takip eder
        self.arp_table = {}  # IP-MAC eşleşmeleri
        self.lock = threading.Lock()

    def start_all(self, app_instance):
        """Tüm hedefler için ARP spoof korumasını başlatır."""
        for target_ip in app_instance.targets:
            self.start(target_ip, app_instance)

    def stop_all(self, app_instance):
        """Tüm aktif koruma işlemlerini durdurur."""
        for target_ip in list(self.threads.keys()):
            self.stop(target_ip, app_instance)

    def start(self, target_ip, app_instance):
        """Belirli bir hedef için ARP spoof korumasını başlatır."""
        if target_ip in self.threads:
            app_instance.log_message(f"{target_ip} için ARP koruması zaten başlatılmış.", 'red')
            return

        thread = threading.Thread(target=self.monitor_arp, args=(target_ip, app_instance), daemon=True)
        self.threads[target_ip] = thread
        thread.start()
        app_instance.log_message(f"ARP spoof koruması başlatıldı: {target_ip}", 'green')

    def stop(self, target_ip, app_instance):
        """Belirli bir hedef için ARP spoof korumasını durdurur."""
        if target_ip in self.threads:
            self.threads.pop(target_ip)
            app_instance.log_message(f"ARP koruması durduruldu: {target_ip}", 'red')
        else:
            app_instance.log_message(f"{target_ip} için aktif ARP koruması bulunamadı.", 'red')

    def monitor_arp(self, target_ip, app_instance):
        """Belirli bir IP adresine yönelik ARP paketlerini izler."""
        try:
            app_instance.log_message(f"{target_ip} için ARP izleme başlatıldı.", 'green')
            
            def process_packet(packet):
                if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP Yanıt Paketi
                    ip = packet[ARP].psrc
                    mac = packet[ARP].hwsrc

                    with self.lock:
                        if ip in self.arp_table and self.arp_table[ip] != mac:
                            app_instance.log_message(
                                f"[!] ARP Spoof Algılandı! {ip} için sahte MAC: {mac}", 'red'
                            )
                            correct_mac = self.get_mac(ip)
                            if correct_mac:
                                self.send_correct_arp(ip, correct_mac)
                            else:
                                app_instance.log_message(
                                    f"[!] {ip} için doğru MAC bulunamadı.", 'red'
                                )
                        else:
                            self.arp_table[ip] = mac

            sniff(filter="arp", prn=process_packet, store=0)

        except Exception as e:
            app_instance.log_message(f"ARP izleme sırasında hata: {e}", 'red')

    def get_mac(self, ip):
        """Doğru MAC adresini öğrenmek için ARP sorgusu gönderir."""
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request

            answered, _ = srp(arp_request_broadcast, timeout=2, verbose=False)
            for _, received in answered:
                return received.hwsrc
        except Exception as e:
            return None

    def send_correct_arp(self, ip, mac):
        """Doğru ARP yanıtı gönderir ve ARP tablosunu düzeltir."""
        arp_response = ARP(op=2, psrc=ip, hwsrc=mac, pdst="192.168.1.1", hwdst="ff:ff:ff:ff:ff:ff")
        send(arp_response, verbose=False)

def setup(app):
    """Plugin'i uygulamaya eklemek için setup fonksiyonu."""
    arp_protection = ARPSpoofProtection()
    arp_protection.filename = "arp_spoof_protection_plugin.py"  # Eklenti dosya adı
    return arp_protection