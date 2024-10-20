import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
from scapy.all import ARP, Ether, srp, sendp, sniff, IP
import netifaces
from mac_vendor_lookup import MacLookup
import time
import platform
import sys
import importlib.util
import os
import socket

# MAC adresi üretici bilgisi almak için MacLookup kullanıyoruz
mac_lookup = MacLookup()
try:
    mac_lookup.update_vendors()  # Vendor veritabanını güncelleyin
except Exception as e:
    print(f"MAC Vendor veritabanı güncellenemedi: {e}", file=sys.stderr)

class NetworkScannerApp:
    def __init__(self, root):
        try:
            self.root = root
            self.root.title("Stallion77 SCR Plugin Manager")
            self.create_widgets()
            self.targets = []
            self.plugins = []  # Yüklenen eklentileri saklamak için
            self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        except Exception as e:
            messagebox.showerror("Başlatma Hatası", f"Uygulama başlatılırken bir hata oluştu:\n{e}")
            self.root.destroy()

    def create_widgets(self):
        try:
            # Menü Çubuğu
            menubar = tk.Menu(self.root)
            self.root.config(menu=menubar)

            # Eklentiler Menüsü
            plugins_menu = tk.Menu(menubar, tearoff=0)
            menubar.add_cascade(label="Eklentiler", menu=plugins_menu)
            plugins_menu.add_command(label="Eklenti Yükle", command=self.load_plugin)

            # Araç Çubuğu
            toolbar = tk.Frame(self.root)
            scan_button = tk.Button(toolbar, text="Ağ Tarama", command=self.scan_network)
            scan_button.pack(side=tk.LEFT, padx=2, pady=2)
            run_plugins_button = tk.Button(toolbar, text="Eklentileri Çalıştır", command=self.run_plugins)
            run_plugins_button.pack(side=tk.LEFT, padx=2, pady=2)
            stop_plugins_button = tk.Button(toolbar, text="Eklentileri Durdur", command=self.stop_plugins)
            stop_plugins_button.pack(side=tk.LEFT, padx=2, pady=2)
            toolbar.pack(side=tk.TOP, fill=tk.X)

            # Ağ Cihazları Listesi
            self.tree = ttk.Treeview(self.root, columns=("IP", "MAC", "Vendor", "Durum"), show='headings')
            self.tree.heading("IP", text="IP Adresi")
            self.tree.heading("MAC", text="MAC Adresi")
            self.tree.heading("Vendor", text="Üretici")
            self.tree.heading("Durum", text="Durum")
            self.tree.pack(fill=tk.BOTH, expand=True)

            # Sağ Tıklama Menüsü (Ağ Cihazları için sadece Hedef Ekleme)
            self.add_menu = tk.Menu(self.root, tearoff=0)
            self.add_menu.add_command(label="Hedef Olarak Ekle", command=self.add_target)

            # Ağ Cihazları Listesi için Sağ Tıklama Olaylarını Bağlama
            if platform.system() == 'Darwin':  # macOS
                self.tree.bind("<Button-2>", self.show_add_context_menu)
                self.tree.bind("<Control-Button-1>", self.show_add_context_menu)  # Ctrl+Click için
            else:
                self.tree.bind("<Button-3>", self.show_add_context_menu)

            # Hedef Cihazlar Listesi
            self.targets_label = tk.Label(self.root, text="Hedef Cihazlar")
            self.targets_label.pack()
            self.targets_list = tk.Listbox(self.root)
            self.targets_list.pack(fill=tk.BOTH, expand=True)

            # Sağ Tıklama Menüsü (Hedef Cihazlar için sadece Cihaz Kaldırma)
            self.remove_menu = tk.Menu(self.root, tearoff=0)
            self.remove_menu.add_command(label="Hedefi Kaldır", command=self.remove_target)

            # Hedef Cihazlar Listesi için Sağ Tıklama Olaylarını Bağlama
            if platform.system() == 'Darwin':  # macOS
                self.targets_list.bind("<Button-2>", self.show_remove_context_menu)
                self.targets_list.bind("<Control-Button-1>", self.show_remove_context_menu)  # Ctrl+Click için
            else:
                self.targets_list.bind("<Button-3>", self.show_remove_context_menu)

            # Log Terminali
            log_label = tk.Label(self.root, text="Log Terminali")
            log_label.pack()
            self.log_text = scrolledtext.ScrolledText(self.root, state='disabled', height=10)
            self.log_text.pack(fill=tk.BOTH, expand=True)
            self.log_text.tag_config('green', foreground='green')
            self.log_text.tag_config('red', foreground='red')
        except Exception as e:
            messagebox.showerror("Widget Oluşturma Hatası", f"Widget'lar oluşturulurken bir hata oluştu:\n{e}")
            self.root.destroy()

    def log_message(self, message, color='green'):
        try:
            self.log_text.configure(state='normal')
            self.log_text.insert(tk.END, message + '\n', color)
            self.log_text.configure(state='disabled')
            self.log_text.see(tk.END)
        except Exception as e:
            print(f"Log mesajı eklenirken hata oluştu: {e}", file=sys.stderr)

    def show_add_context_menu(self, event):
        try:
            # Menüye tıklanan satırı seç
            selected_item = self.tree.identify_row(event.y)
            if selected_item:
                self.tree.selection_set(selected_item)
                # Menüyi göster
                self.add_menu.post(event.x_root, event.y_root)
        except Exception as e:
            print(f"Sağ tıklama menüsü gösterilirken hata oluştu: {e}", file=sys.stderr)
        finally:
            self.add_menu.grab_release()

    def show_remove_context_menu(self, event):
        try:
            # Menüye tıklanan satırı seç
            selected_index = self.targets_list.nearest(event.y)
            if selected_index >= 0:
                self.targets_list.selection_clear(0, tk.END)
                self.targets_list.selection_set(selected_index)
                # Menüyi göster
                self.remove_menu.post(event.x_root, event.y_root)
        except Exception as e:
            print(f"Sağ tıklama menüsü gösterilirken hata oluştu: {e}", file=sys.stderr)
        finally:
            self.remove_menu.grab_release()

    def add_target(self):
        try:
            selected = self.tree.focus()
            if selected:
                values = self.tree.item(selected, 'values')
                ip, mac, vendor, durum = values
                if ip not in self.targets:
                    self.targets.append(ip)
                    self.targets_list.insert(tk.END, f"{ip} ({vendor})")
                    self.log_message(f"Hedef eklendi: {ip}", 'green')
                else:
                    messagebox.showinfo("Bilgi", "Cihaz zaten hedef listesinde.")
        except Exception as e:
            messagebox.showerror("Hata", f"Hedef eklenirken bir hata oluştu:\n{e}")

    def remove_target(self):
        try:
            selected_indices = self.targets_list.curselection()
            if not selected_indices:
                messagebox.showwarning("Uyarı", "Lütfen kaldırmak istediğiniz cihazları seçin.")
                return

            for index in selected_indices[::-1]:  # Reverse iterate to avoid index issues
                target_entry = self.targets_list.get(index)
                ip = target_entry.split(' ')[0]  # Extract IP address
                if ip in self.targets:
                    self.targets.remove(ip)
                    self.targets_list.delete(index)
                    self.log_message(f"Hedef kaldırıldı: {ip}", 'red')

                    # Eklentilere hedef kaldırıldığını bildirin
                    for plugin in self.plugins:
                        if hasattr(plugin, 'stop'):
                            gateway_ip = self.get_gateway_ip()
                            iface = self.get_interface()
                            plugin.stop(ip, gateway_ip, iface, self)
        except Exception as e:
            messagebox.showerror("Hata", f"Hedef kaldırılırken bir hata oluştu:\n{e}")

    def load_plugin(self):
        try:
            plugin_path = filedialog.askopenfilename(title="Eklenti Yükle", filetypes=[("Python Files", "*.py")])
            if plugin_path:
                spec = importlib.util.spec_from_file_location("plugin_module", plugin_path)
                plugin_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(plugin_module)
                if hasattr(plugin_module, 'setup'):
                    plugin_instance = plugin_module.setup(self)
                    if plugin_instance and plugin_instance not in self.plugins:
                        self.plugins.append(plugin_instance)
                        plugin_filename = os.path.basename(plugin_path)
                        self.log_message(f"Eklenti yüklendi: {plugin_filename}", 'green')
                    else:
                        messagebox.showerror("Hata", "Eklenti çalıştırılırken bir hata oluştu veya eklenti zaten yüklü.")
                else:
                    messagebox.showerror("Hata", "Eklenti dosyası 'setup' fonksiyonunu içermiyor.")
        except Exception as e:
            messagebox.showerror("Hata", f"Eklenti yüklenirken bir hata oluştu: {e}")
            self.log_message(f"Eklenti yüklenirken hata: {e}", 'red')

    def run_plugins(self):
        try:
            for plugin in self.plugins:
                if hasattr(plugin, 'start_all'):
                    plugin.start_all(self)
            self.log_message("Tüm eklentiler çalıştırıldı.", 'green')
        except Exception as e:
            messagebox.showerror("Hata", f"Eklentiler çalıştırılırken bir hata oluştu:\n{e}")
            self.log_message(f"Eklentiler çalıştırılırken hata: {e}", 'red')

    def stop_plugins(self):
        try:
            for plugin in self.plugins:
                if hasattr(plugin, 'stop_all'):
                    plugin.stop_all(self)
            self.log_message("Tüm eklentiler durduruldu.", 'red')
        except Exception as e:
            messagebox.showerror("Hata", f"Eklentiler durdurulurken bir hata oluştu:\n{e}")
            self.log_message(f"Eklentiler durdurulurken hata: {e}", 'red')

    def scan_network(self):
        try:
            threading.Thread(target=self.perform_scan, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Hata", f"Ağ taraması başlatılırken bir hata oluştu:\n{e}")

    def perform_scan(self):
        try:
            self.tree.delete(*self.tree.get_children())  # Mevcut cihaz listesini temizle
            local_ip = self.get_local_ip()  # Yerel IP'yi al
            ip_parts = local_ip.split('.')
            if len(ip_parts) != 4:
                self.log_message("Yerel IP adresi geçersiz.", 'red')
                return
            network = '.'.join(ip_parts[:3]) + '.0/24'  # /24 ağını hesapla

            arp = ARP(pdst=network)  # Ağda ARP taraması yap
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast paketi
            packet = ether / arp

            try:
                result = srp(packet, timeout=3, verbose=0)[0]  # Cihazları bul
            except Exception as e:
                messagebox.showerror("Hata", f"Ağ tarama sırasında bir hata oluştu: {e}")
                return

            devices = []
            local_device_found = False  # Yerel cihazı bulma kontrolü

            # Tarama sonuçlarını işle
            for sent, received in result:
                try:
                    vendor = mac_lookup.lookup(received.hwsrc)
                except Exception as e:
                    vendor = "Bilinmiyor"
                    print(f"Vendor lookup hatası: {e}", file=sys.stderr)

                devices.append((received.psrc, received.hwsrc, vendor, "Eklenti Bekliyor"))

                # Yerel cihazın tarama sonucunda görünüp görünmediğini kontrol et
                if received.psrc == local_ip:
                    local_device_found = True

            # Yerel cihazı listede bulamazsak elle ekle
            if not local_device_found:
                try:
                    local_mac = self.get_local_mac()  # Yerel MAC adresini al
                    vendor = mac_lookup.lookup(local_mac) if local_mac else "Bilinmiyor"
                    devices.append((local_ip, local_mac, vendor, "Yerel Cihaz"))
                except Exception as e:
                    self.log_message(f"Yerel cihaz eklenirken hata: {e}", 'red')

            # Cihazları listeye ekle
            for device in devices:
                self.tree.insert("", tk.END, values=device)
        except Exception as e:
            self.log_message(f"Ağ taraması sırasında hata oluştu: {e}", 'red')

    def on_close(self):
        try:
            # Tüm eklentileri durdur
            for plugin in self.plugins:
                if hasattr(plugin, 'stop_all'):
                    plugin.stop_all(self)
            self.root.destroy()
        except Exception as e:
            print(f"Uygulama kapanırken hata oluştu: {e}", file=sys.stderr)
            self.root.destroy()

    def get_interface(self):
        try:
            local_ip = self.get_local_ip()
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                addresses = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addresses:
                    for link in addresses[netifaces.AF_INET]:
                        ip = link.get('addr')
                        if ip == local_ip:
                            return iface
            return None
        except Exception as e:
            self.log_message(f"Ağ arayüzü alınırken hata oluştu: {e}", 'red')
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
            self.log_message(f"Yerel IP alınırken hata oluştu: {e}", 'red')
            return "127.0.0.1"

    def get_local_mac(self):
        """Yerel cihazın MAC adresini alır."""
        try:
            local_ip = self.get_local_ip()
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                addresses = netifaces.ifaddresses(iface)
                if netifaces.AF_LINK in addresses:
                    for link in addresses[netifaces.AF_LINK]:
                        mac = link.get('addr')
                        if mac and len(mac.split(':')) == 6:
                            if netifaces.AF_INET in addresses:
                                for link_in in addresses[netifaces.AF_INET]:
                                    ip = link_in.get('addr')
                                    if ip == local_ip:
                                        return mac
            return None
        except Exception as e:
            self.log_message(f"Yerel MAC alınırken hata oluştu: {e}", 'red')
            return None

    def get_gateway_ip(self):
        """Varsayılan gateway IP adresini alır."""
        try:
            gateways = netifaces.gateways()
            return gateways['default'][netifaces.AF_INET][0]
        except Exception as e:
            self.log_message(f"Gateway IP alınırken hata oluştu: {e}", 'red')
            return None

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = NetworkScannerApp(root)
        root.mainloop()
    except Exception as e:
        print(f"Uygulama çalıştırılırken hata oluştu: {e}", file=sys.stderr)
