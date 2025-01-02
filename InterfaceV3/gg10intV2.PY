import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk, simpledialog
import subprocess
import os
import sys
import threading
import json

# DÃ©finir les couleurs de la palette
COLOR_PRIMARY = "#2C3E50"    # Bleu Nuit
COLOR_SECONDARY = "#3498DB"  # Bleu Clair
COLOR_ACCENT = "#1ABC9C"     # Vert Menthe
COLOR_NEUTRAL = "#ECF0F1"    # Gris Clair
COLOR_TEXT = "#FFFFFF"       # Blanc
COLOR_DANGER = "#E74C3C"     # Rouge pour actions critiques
COLOR_SUCCESS = "#2ECC71"     # Vert pour succÃ¨s
COLOR_ERROR = "#E74C3C"       # Rouge pour erreurs

# DÃ©finir les polices
FONT_TITLE = ("Helvetica", 16, "bold")
FONT_LABEL = ("Helvetica", 12)
FONT_BUTTON = ("Helvetica", 12)
FONT_TEXT = ("Courier New", 10)

class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Gestionnaire de Trafic RÃ©seau")
        self.geometry("1200x800")  # AjustÃ© pour accueillir le Treeview
        self.resizable(False, False)
        self.configure(bg=COLOR_PRIMARY)

        # Appliquer un thÃ¨me ttk
        style = ttk.Style(self)
        style.theme_use('clam')  # 'clam', 'alt', 'default', 'classic'

        # DÃ©finir les styles personnalisÃ©s
        style.configure("Accent.TButton",
                        foreground=COLOR_TEXT,
                        background=COLOR_ACCENT,
                        font=FONT_BUTTON)
        style.map("Accent.TButton",
                  background=[("active", COLOR_SECONDARY)])

        style.configure("Danger.TButton",
                        foreground=COLOR_TEXT,
                        background=COLOR_DANGER,
                        font=FONT_BUTTON)
        style.map("Danger.TButton",
                  background=[("active", "#C0392B")])

        style.configure("Success.TLabel",
                        foreground=COLOR_SUCCESS,
                        background=COLOR_PRIMARY,
                        font=FONT_LABEL)
        style.configure("Error.TLabel",
                        foreground=COLOR_ERROR,
                        background=COLOR_PRIMARY,
                        font=FONT_LABEL)
        style.configure("Neutral.TLabel",
                        foreground=COLOR_TEXT,
                        background=COLOR_PRIMARY,
                        font=FONT_LABEL)

        # Variables pour le processus
        self.process = None
        self.stop_event = threading.Event()

        # Dictionnaire des IP et ports autorisÃ©s
        self.allowed_ips_ports = {
            "192.168.0.193": {
                "tcp": [8080],
                "udp": []
            },
            "any": {  # EntrÃ©e spÃ©ciale pour autoriser n'importe quelle IP
                "tcp": [80, 443],
                "udp": [53, 67, 68, 123]
            }
        }

        # CrÃ©ation des widgets
        self.create_widgets()

    def create_widgets(self):
        # Titre de l'application
        title_label = tk.Label(self, text="Gestionnaire de Trafic RÃ©seau", font=FONT_TITLE, bg=COLOR_PRIMARY, fg=COLOR_TEXT)
        title_label.pack(pady=10)

        # Frame pour les boutons Execute et Stop
        button_frame = tk.Frame(self, bg=COLOR_PRIMARY)
        button_frame.pack(pady=10)

        # Bouton Execute
        self.execute_button = ttk.Button(button_frame, text="Execute", command=self.execute_program, style="Accent.TButton")
        self.execute_button.grid(row=0, column=0, padx=10, pady=5)

        # Bouton Stop
        self.stop_button = ttk.Button(button_frame, text="Stop", command=self.stop_program, style="Danger.TButton")
        self.stop_button.grid(row=0, column=1, padx=10, pady=5)
        self.stop_button.state(['disabled'])  # DÃ©sactiver au dÃ©part

        # Indicateur d'Ã©tat
        self.status_label = ttk.Label(self, text="Ã‰tat : ArrÃªtÃ©", style="Neutral.TLabel")
        self.status_label.pack(pady=5)

        # Section pour gÃ©rer les allowed_ips et leurs ports
        ips_ports_frame = ttk.LabelFrame(self, text="GÃ©rer les Adresses IP et leurs Ports AutorisÃ©s", padding=(10, 10))
        ips_ports_frame.pack(pady=10, padx=10, fill="both", expand=True)

        # Treeview pour afficher les IPs et leurs ports
        self.tree = ttk.Treeview(ips_ports_frame, columns=("Protocol", "Port"), show="tree headings")
        self.tree.heading("#0", text="Adresse IP / Protocole")
        self.tree.heading("Protocol", text="Protocole")
        self.tree.heading("Port", text="Port AutorisÃ©")
        self.tree.column("#0", width=300, anchor='w')
        self.tree.column("Protocol", width=100, anchor='center')
        self.tree.column("Port", width=100, anchor='center')
        self.tree.pack(side="left", fill="both", expand=True, padx=(0,10), pady=5)

        # Scrollbar pour le Treeview
        scrollbar = ttk.Scrollbar(ips_ports_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side="left", fill="y")

        # Boutons pour gÃ©rer les IPs et Ports
        ips_ports_buttons_frame = tk.Frame(ips_ports_frame, bg=COLOR_PRIMARY)
        ips_ports_buttons_frame.pack(side="left", fill="y", pady=5)

        # Bouton Ajouter IP avec style Accent
        add_ip_button = ttk.Button(ips_ports_buttons_frame, text="Ajouter IP", command=self.add_ip, style="Accent.TButton")
        add_ip_button.pack(pady=5, fill="x")

        # Bouton Supprimer IP avec style Danger
        remove_ip_button = ttk.Button(ips_ports_buttons_frame, text="Supprimer IP", command=self.remove_ip, style="Danger.TButton")
        remove_ip_button.pack(pady=5, fill="x")

        # Bouton Ajouter Port avec style Accent
        add_port_button = ttk.Button(ips_ports_buttons_frame, text="Ajouter Port", command=self.add_port, style="Accent.TButton")
        add_port_button.pack(pady=5, fill="x")

        # Bouton Supprimer Port avec style Danger
        remove_port_button = ttk.Button(ips_ports_buttons_frame, text="Supprimer Port", command=self.remove_port, style="Danger.TButton")
        remove_port_button.pack(pady=5, fill="x")


        # Remplir le Treeview avec les IPs et leurs ports autorisÃ©s
        self.populate_tree()

        # SÃ©parateur
        separator2 = ttk.Separator(self, orient='horizontal')
        separator2.pack(fill='x', padx=5, pady=10)

        # Section pour l'affichage des sorties
        output_frame = ttk.LabelFrame(self, text="Sorties du Programme", padding=(10, 10))
        output_frame.pack(pady=10, padx=10, fill="both", expand=True)

        # Ajouter une Ã©tiquette au-dessus de la zone de texte
        output_label = ttk.Label(output_frame, text="Sorties du Programme", font=FONT_LABEL)
        output_label.pack(anchor='w', pady=(0, 5))

        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, font=FONT_TEXT, state='disabled')
        self.output_text.pack(fill="both", expand=True, padx=5, pady=5)

    def populate_tree(self):
        # Effacer le Treeview
        for item in self.tree.get_children():
            self.tree.delete(item)
        # Ajouter les IPs et leurs ports autorisÃ©s
        for ip, protocols in self.allowed_ips_ports.items():
            ip_display = ip.upper() if ip.lower() == "any" else ip
            ip_item = self.tree.insert("", "end", text=ip_display, values=("", ""), open=True)
            for protocol, ports in protocols.items():
                protocol_item = self.tree.insert(ip_item, "end", text=f"{protocol.upper()}", values=(protocol.upper(), ""), open=True)
                for port in sorted(ports):
                    self.tree.insert(protocol_item, "end", text=f"{port}", values=("", port))

    def add_ip(self):
        ip = simpledialog.askstring("Ajouter IP", "Entrez l'adresse IP Ã  ajouter (ou 'any' pour autoriser toutes les IPs):")
        if ip:
            ip = ip.strip().lower()
            if ip == "any":
                display_ip = "ANY"
                key_ip = "any"
            else:
                if self.validate_ip(ip):
                    display_ip = ip
                    key_ip = ip
                else:
                    messagebox.showerror("Erreur", "Adresse IP invalide.")
                    return

            if key_ip not in self.allowed_ips_ports:
                # Initialiser les listes de ports TCP et UDP
                self.allowed_ips_ports[key_ip] = {"tcp": [], "udp": []}
                self.populate_tree()
            else:
                messagebox.showwarning("Attention", "Cette adresse IP est dÃ©jÃ  dans la liste.")

    def remove_ip(self):
        selected = self.tree.selection()
        if selected:
            item = selected[0]
            parent = self.tree.parent(item)
            if parent:  # Si c'est un protocole ou un port, ignore
                messagebox.showwarning("Attention", "Veuillez sÃ©lectionner une adresse IP, pas un protocole ou un port.")
                return
            ip_display = self.tree.item(item, "text")
            key_ip = "any" if ip_display.upper() == "ANY" else self.tree.item(item, "text")
            confirm = messagebox.askyesno("Confirmer", f"Voulez-vous vraiment supprimer l'adresse IP '{ip_display}' et tous ses ports autorisÃ©s?")
            if confirm:
                if key_ip in self.allowed_ips_ports:
                    del self.allowed_ips_ports[key_ip]
                    self.populate_tree()
        else:
            messagebox.showwarning("Attention", "Veuillez sÃ©lectionner une adresse IP Ã  supprimer.")

    def add_port(self):
        selected = self.tree.selection()
        if selected:
            item = selected[0]
            item_depth = self.get_item_depth(item)
            if item_depth == 1:  # Protocole
                ip_item = self.tree.parent(item)
                ip_display = self.tree.item(ip_item, "text")
                key_ip = "any" if ip_display.upper() == "ANY" else ip_display
                protocol = self.tree.item(item, "values")[0].lower()
            elif item_depth == 2:  # Port
                protocol_item = self.tree.parent(item)
                ip_item = self.tree.parent(protocol_item)
                ip_display = self.tree.item(ip_item, "text")
                key_ip = "any" if ip_display.upper() == "ANY" else ip_display
                protocol = self.tree.item(protocol_item, "values")[0].lower()
            else:
                messagebox.showwarning("Attention", "Veuillez sÃ©lectionner un protocole ou une adresse IP pour ajouter un port.")
                return

            # Demander le protocole si l'utilisateur sÃ©lectionne une adresse IP
            if item_depth == 0:
                protocol = simpledialog.askstring("Protocole", "Entrez le protocole pour ajouter le port (TCP/UDP):")
                if protocol:
                    protocol = protocol.lower()
                    if protocol not in ["tcp", "udp"]:
                        messagebox.showerror("Erreur", "Protocole invalide. Veuillez entrer TCP ou UDP.")
                        return
                else:
                    return  # Annuler si aucun protocole n'est entrÃ©

            port = simpledialog.askinteger("Ajouter Port", f"Entrez le numÃ©ro de port Ã  ajouter pour {ip_display} ({protocol.upper()}):",
                                           minvalue=1, maxvalue=65535)
            if port:
                if port not in self.allowed_ips_ports[key_ip][protocol]:
                    self.allowed_ips_ports[key_ip][protocol].append(port)
                    self.populate_tree()
                else:
                    messagebox.showwarning("Attention", f"Le port {port} est dÃ©jÃ  autorisÃ© pour {ip_display} ({protocol.upper()}).")
        else:
            messagebox.showwarning("Attention", "Veuillez sÃ©lectionner une adresse IP ou un protocole pour ajouter un port.")

    def remove_port(self):
        selected = self.tree.selection()
        if selected:
            item = selected[0]
            item_depth = self.get_item_depth(item)
            if item_depth != 2:  # Assurez-vous que c'est un port
                messagebox.showwarning("Attention", "Veuillez sÃ©lectionner un port Ã  supprimer.")
                return

            protocol_item = self.tree.parent(item)
            ip_item = self.tree.parent(protocol_item)
            ip_display = self.tree.item(ip_item, "text")
            key_ip = "any" if ip_display.upper() == "ANY" else self.tree.item(ip_item, "text")
            protocol = self.tree.item(protocol_item, "values")[0].lower()
            port_text = self.tree.item(item, "text")
            try:
                port = int(port_text)
                print(f"Tentative de suppression du port {port} pour {ip_display} ({protocol.upper()})")  # Log
                confirm = messagebox.askyesno("Confirmer", f"Voulez-vous vraiment supprimer le port {port} de {ip_display} ({protocol.upper()})?")
                if confirm:
                    if port in self.allowed_ips_ports[key_ip][protocol]:
                        self.allowed_ips_ports[key_ip][protocol].remove(port)
                        print(f"Port {port} supprimÃ© de {ip_display} ({protocol.upper()})")  # Log
                        self.populate_tree()
                    else:
                        messagebox.showerror("Erreur", f"Le port {port} n'est pas dans la liste des ports autorisÃ©s pour {ip_display} ({protocol.upper()}).")
            except ValueError:
                messagebox.showerror("Erreur", "Format de port invalide.")
        else:
            messagebox.showwarning("Attention", "Veuillez sÃ©lectionner un port Ã  supprimer.")

    def get_item_depth(self, item):
        depth = 0
        parent = self.tree.parent(item)
        while parent:
            depth += 1
            parent = self.tree.parent(parent)
        return depth

    def validate_ip(self, ip):
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            for part in parts:
                if not 0 <= int(part) <= 255:
                    return False
            return True
        except ValueError:
            return False

    def execute_program(self):
        if self.process is None:
            try:
                # Construction du chemin vers gg10.py
                script_path = os.path.join(os.getcwd(), "gg10.py")
                if not os.path.isfile(script_path):
                    messagebox.showerror("Erreur", f"Le fichier {script_path} n'existe pas.")
                    return

                # PrÃ©parer les arguments pour allowed_ips_ports sous forme JSON
                config_serializable = {ip: {"tcp": sorted(list(ports["tcp"])), "udp": sorted(list(ports["udp"]))} 
                                       for ip, ports in self.allowed_ips_ports.items()}
                config_json = json.dumps(config_serializable)

                # Lancement du script gg10.py avec allowed_ips_ports comme argument JSON
                self.process = subprocess.Popen(
                    [sys.executable, script_path, "--config", config_json],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,  # Pour obtenir des chaÃ®nes de caractÃ¨res
                    bufsize=1,  # Ligne par ligne
                    universal_newlines=True
                )

                # RÃ©initialiser l'Ã©vÃ©nement d'arrÃªt
                self.stop_event.clear()

                # Mettre Ã  jour l'Ã©tat
                self.update_status(running=True)

                # DÃ©marrer les threads pour lire stdout et stderr
                threading.Thread(target=self.read_stdout, daemon=True).start()
                threading.Thread(target=self.read_stderr, daemon=True).start()

                self.append_text("Programme exÃ©cutÃ© avec succÃ¨s.\n")
            except Exception as e:
                messagebox.showerror("Erreur", f"Impossible d'exÃ©cuter le programme.\n{e}")
        else:
            messagebox.showwarning("Attention", "Le programme est dÃ©jÃ  en cours d'exÃ©cution.")

    def stop_program(self):
        if self.process is not None:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
                self.append_text("Programme arrÃªtÃ© avec succÃ¨s.\n")
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.append_text("Le programme a Ã©tÃ© forcÃ© Ã  s'arrÃªter.\n")
            except Exception as e:
                messagebox.showerror("Erreur", f"Impossible d'arrÃªter le programme.\n{e}")
            finally:
                self.process = None
                self.stop_event.set()
                # Mettre Ã  jour l'Ã©tat
                self.update_status(running=False)
        else:
            messagebox.showwarning("Attention", "Aucun programme en cours d'exÃ©cution.")

    def read_stdout(self):
        try:
            for line in self.process.stdout:
                if self.stop_event.is_set():
                    break
                self.append_text(line)
        except Exception as e:
            self.append_text(f"Erreur lecture stdout: {e}\n")

    def read_stderr(self):
        try:
            for line in self.process.stderr:
                if self.stop_event.is_set():
                    break
                self.append_text(f"ERREUR: {line}")
        except Exception as e:
            self.append_text(f"Erreur lecture stderr: {e}\n")

    def append_text(self, text):
        self.output_text.configure(state='normal')
        self.output_text.insert(tk.END, text)
        self.output_text.see(tk.END)
        self.output_text.configure(state='disabled')

    def update_status(self, running):
        if running:
            self.status_label.config(text="Ã‰tat : En cours d'exÃ©cution", style="Success.TLabel")
            self.execute_button.state(['disabled'])
            self.stop_button.state(['!disabled'])
        else:
            self.status_label.config(text="Ã‰tat : ArrÃªtÃ©", style="Neutral.TLabel")
            self.execute_button.state(['!disabled'])
            self.stop_button.state(['disabled'])

    def on_closing(self):
        if self.process is not None:
            self.stop_program()
        self.destroy()

if __name__ == "__main__":
    app = Application()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()