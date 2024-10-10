# port_scanner_plugin.py

import threading
import socket
from queue import Queue

class PortScanner:
    def __init__(self):
        self.threads = {}
        self.open_ports = {}
        self.lock = threading.Lock()

    def start_all(self, app_instance):
        for target_ip in app_instance.targets:
            self.start(target_ip, app_instance)

    def stop_all(self, app_instance):
        for target_ip in list(self.threads.keys()):
            self.stop(target_ip, app_instance)

    def start(self, target_ip, app_instance):
        if target_ip in self.threads:
            app_instance.log_message(f"{target_ip} için Port taraması zaten başlatılmış.", 'red')
            return

        thread = threading.Thread(target=self.scan_ports, args=(target_ip, app_instance), daemon=True)
        self.threads[target_ip] = thread
        thread.start()
        app_instance.log_message(f"Port taraması başlatıldı: {target_ip}", 'green')

    def stop(self, target_ip, app_instance):
        if target_ip in self.threads:
            # Port tarama işlemi durdurulamıyor çünkü tarama tamamlanır tamamlanmaz thread sona erer
            self.threads.pop(target_ip)
            app_instance.log_message(f"Port taraması durduruldu: {target_ip}", 'red')
        else:
            app_instance.log_message(f"{target_ip} için aktif Port taraması bulunamadı.", 'red')

    def scan_ports(self, target_ip, app_instance):
        try:
            open_ports = []
            app_instance.log_message(f"Port taraması başlatılıyor: {target_ip}", 'green')
            port_queue = Queue()

            # Tüm portları kuyruğa ekleyin
            for port in range(1, 65536):  # 1 ile 65535 arasındaki portları tarar
                port_queue.put(port)

            def worker():
                while not port_queue.empty():
                    port = port_queue.get()
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.settimeout(0.1)  # Timeout süresini azaltın
                            result = s.connect_ex((target_ip, port))
                            if result == 0:
                                with self.lock:
                                    open_ports.append(port)
                                app_instance.log_message(f"{target_ip} üzerinde açık port bulundu: {port}", 'green')
                    except Exception as e:
                        app_instance.log_message(f"Port taraması sırasında hata ({target_ip}, Port {port}): {e}", 'red')
                    finally:
                        port_queue.task_done()

            num_threads = 100  # Paralel tarama için iş parçacığı sayısı
            threads = []
            for _ in range(num_threads):
                t = threading.Thread(target=worker, daemon=True)
                t.start()
                threads.append(t)

            # Tüm portlar tarandıktan sonra bekleyin
            port_queue.join()

            if open_ports:
                open_ports_sorted = sorted(open_ports)
                app_instance.log_message(f"{target_ip} üzerinde açık portlar: {open_ports_sorted}", 'green')
            else:
                app_instance.log_message(f"{target_ip} üzerinde hiçbir açık port bulunamadı.", 'green')

            # Tarama tamamlandıktan sonra thread'i listeden çıkarın
            self.threads.pop(target_ip, None)

        except Exception as e:
            app_instance.log_message(f"Port taraması sırasında genel hata ({target_ip}): {e}", 'red')

def setup(app):
    port_scanner = PortScanner()
    port_scanner.filename = "port_scanner_plugin.py"  # Eklenti dosya adını belirlemek için
    return port_scanner
