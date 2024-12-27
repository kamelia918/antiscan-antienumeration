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
        self.geometry("900x800")  # AjustÃ© pour accueillir le Treeview
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
            "192.168.0.193": {8080}  # IP par dÃ©faut avec port par dÃ©faut
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
        self.tree = ttk.Treeview(ips_ports_frame, columns=("Ports"), show="tree headings")
        self.tree.heading("#0", text="Adresse IP")
        self.tree.heading("Ports", text="Ports AutorisÃ©s")
        self.tree.column("#0", width=200)
        self.tree.column("Ports", width=200)
        self.tree.pack(side="left", fill="both", expand=True, padx=(0,10), pady=5)

        # Scrollbar pour le Treeview
        scrollbar = ttk.Scrollbar(ips_ports_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side="left", fill="y")

        # Boutons pour gÃ©rer les IPs et Ports
        ips_ports_buttons_frame = tk.Frame(ips_ports_frame, bg=COLOR_PRIMARY)
        ips_ports_buttons_frame.pack(side="left", fill="y", pady=5)

        add_ip_button = ttk.Button(ips_ports_buttons_frame, text="Ajouter IP", command=self.add_ip)
        add_ip_button.pack(pady=5, fill="x")

        remove_ip_button = ttk.Button(ips_ports_buttons_frame, text="Supprimer IP", command=self.remove_ip)
        remove_ip_button.pack(pady=5, fill="x")

        add_port_button = ttk.Button(ips_ports_buttons_frame, text="Ajouter Port", command=self.add_port)
        add_port_button.pack(pady=5, fill="x")

        remove_port_button = ttk.Button(ips_ports_buttons_frame, text="Supprimer Port", command=self.remove_port)
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
        # Ajouter les IPs et leurs ports
        for ip, ports in self.allowed_ips_ports.items():
            ports_str = ", ".join(map(str, sorted(ports)))
            parent = self.tree.insert("", "end", text=ip, values=(ports_str,))
            for port in sorted(ports):
                self.tree.insert(parent, "end", text=f"Port {port}", values=("",))

    def add_ip(self):
        ip = simpledialog.askstring("Ajouter IP", "Entrez l'adresse IP Ã  ajouter:")
        if ip:
            ip = ip.strip()
            if self.validate_ip(ip):
                if ip not in self.allowed_ips_ports:
                    self.allowed_ips_ports[ip] = set()
                    self.populate_tree()
                else:
                    messagebox.showwarning("Attention", "Cette adresse IP est dÃ©jÃ  dans la liste.")
            else:
                messagebox.showerror("Erreur", "Adresse IP invalide.")

    def remove_ip(self):
        selected = self.tree.selection()
        if selected:
            item = selected[0]
            parent = self.tree.parent(item)
            if parent:  # Si c'est un port, ignore
                messagebox.showwarning("Attention", "Veuillez sÃ©lectionner une adresse IP, pas un port.")
                return
            ip = self.tree.item(item, "text")
            confirm = messagebox.askyesno("Confirmer", f"Voulez-vous vraiment supprimer l'adresse IP {ip} et tous ses ports autorisÃ©s?")
            if confirm:
                if ip in self.allowed_ips_ports:
                    del self.allowed_ips_ports[ip]
                    self.populate_tree()
        else:
            messagebox.showwarning("Attention", "Veuillez sÃ©lectionner une adresse IP Ã  supprimer.")

    def add_port(self):
        selected = self.tree.selection()
        if selected:
            item = selected[0]
            parent = self.tree.parent(item)
            if parent:  # Si un port est sÃ©lectionnÃ©, obtenir l'IP parent
                ip = self.tree.item(parent, "text")
            else:
                ip = self.tree.item(item, "text")
            port = simpledialog.askinteger("Ajouter Port", f"Entrez le numÃ©ro de port Ã  ajouter pour {ip}:",
                                           minvalue=1, maxvalue=65535)
            if port:
                if port not in self.allowed_ips_ports[ip]:
                    self.allowed_ips_ports[ip].add(port)
                    self.populate_tree()
                else:
                    messagebox.showwarning("Attention", f"Le port {port} est dÃ©jÃ  autorisÃ© pour {ip}.")
        else:
            messagebox.showwarning("Attention", "Veuillez sÃ©lectionner une adresse IP pour ajouter un port.")

    def remove_port(self):
        selected = self.tree.selection()
        if selected:
            item = selected[0]
            parent = self.tree.parent(item)
            if not parent:
                messagebox.showwarning("Attention", "Veuillez sÃ©lectionner un port Ã  supprimer, pas une adresse IP.")
                return
            ip = self.tree.item(parent, "text")
            port_text = self.tree.item(item, "text")
            try:
                port = int(port_text.replace("Port ", ""))
                confirm = messagebox.askyesno("Confirmer", f"Voulez-vous vraiment supprimer le port {port} de {ip}?")
                if confirm:
                    if port in self.allowed_ips_ports[ip]:
                        self.allowed_ips_ports[ip].remove(port)
                        self.populate_tree()
            except ValueError:
                messagebox.showerror("Erreur", "Format de port invalide.")
        else:
            messagebox.showwarning("Attention", "Veuillez sÃ©lectionner un port Ã  supprimer.")

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
                config_serializable = {ip: list(ports) for ip, ports in self.allowed_ips_ports.items()}
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