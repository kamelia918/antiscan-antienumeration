import time
import pydivert
from prettytable import PrettyTable
from collections import defaultdict

# Liste des adresses IP suspectes et compteur d'activités
suspect_ips = {}
activity_counter = defaultdict(lambda: {"ports": set(), "timestamp": time.time()})

BLOCK_DURATION = 60  # Temps de blocage en secondes
SCAN_THRESHOLD = 5  # Nombre de ports différents touchés dans un intervalle court
TIME_WINDOW = 10  # Intervalle de temps pour analyser les activités (en secondes)
SAFE_PORTS = {}  # Ports à ignorer (DNS, mDNS, etc.)
INTERNAL_IPS = {}  # Adresses internes à ignorer

# Fonction pour bloquer temporairement une adresse IP
def block_ip(ip):
    print(f"Blocage temporaire de l'adresse IP {ip}")
    suspect_ips[ip] = time.time() + BLOCK_DURATION  # Marque l'IP comme bloquée pour une durée déterminée

# Fonction pour afficher le tableau des adresses bloquées
def display_blocked_ips():
    table = PrettyTable()
    table.field_names = ["Adresse IP", "Temps restant (s)"]
    current_time = time.time()

    for ip, unblock_time in suspect_ips.items():
        if unblock_time > current_time:
            remaining_time = int(unblock_time - current_time)
            table.add_row([ip, remaining_time])

    if table.rowcount > 0:
        print("\nTableau des adresses bloquées :")
        print(table)
    else:
        print("\nAucune adresse bloquée actuellement.")

# Fonction pour analyser les activités réseau
def analyze_activity(ip, port):
    current_time = time.time()
    activity = activity_counter[ip]

    # Réinitialiser l'activité si le délai est dépassé
    if current_time - activity["timestamp"] > TIME_WINDOW:
        activity["ports"].clear()
        activity["timestamp"] = current_time

    # Ajouter le port à l'ensemble des ports touchés
    activity["ports"].add(port)

    # Si le nombre de ports uniques dépasse le seuil, considérer comme un scan
    if len(activity["ports"]) >= SCAN_THRESHOLD:
        block_ip(ip)
        activity_counter[ip] = {"ports": set(), "timestamp": current_time}  # Réinitialiser après blocage

# Capture de paquets avec WinDivert
with pydivert.WinDivert("true") as w:
    print("Capture des paquets en cours...")
    for packet in w:
        try:
            if packet.is_inbound:
                src_ip = packet.src_addr
                dst_port = packet.dst_port

                # Mise à jour et affichage du tableau des adresses bloquées
                display_blocked_ips()

                # Si l'IP est bloquée et le temps de blocage n'est pas écoulé
                if src_ip in suspect_ips and time.time() < suspect_ips[src_ip]:
                    # Autoriser uniquement les paquets ICMP
                    if packet.icmp:
                        print(f"ICMP (ping) reçu de {src_ip}, autorisé")
                        w.send(packet)  # Réinjecte le paquet ICMP sans modification
                    continue  # Ne pas traiter les autres paquets de cette IP

                # Si l'IP est bloquée mais le temps de blocage est écoulé
                if src_ip in suspect_ips and time.time() >= suspect_ips[src_ip]:
                    print(f"Déblocage de l'adresse IP {src_ip}")
                    del suspect_ips[src_ip]  # Retirer l'IP de la liste des bloqués

                # Si le paquet est un ICMP (ping), autoriser toujours
                if packet.icmp:
                    print(f"ICMP (ping) reçu de {src_ip}, autorisé")
                    w.send(packet)  # Réinjecte le paquet ICMP sans modification
                    continue

                # Ignorer les adresses internes ou sûres
                if src_ip in INTERNAL_IPS:
                    w.send(packet)  # Réinjecter ces paquets normalement
                    continue

                # Ignorer les ports sécurisés (par exemple, DNS, mDNS)
                if dst_port in SAFE_PORTS:
                    w.send(packet)  # Réinjecter ces paquets normalement
                    continue

                # Détection des scans (TCP SYN, FIN, XMAS ou UDP)
                if (packet.tcp and (packet.tcp.syn or packet.tcp.fin or (packet.tcp.psh and packet.tcp.urg and packet.tcp.fin))) or packet.udp:
                    print(f"Activité détectée de {src_ip} sur le port {dst_port}")
                    analyze_activity(src_ip, dst_port)
                    continue  # Bloquer immédiatement après détection du scan

            # Réinjecter les paquets non-suspects
            w.send(packet)

        except Exception as e:
            print(f"Erreur: {e}")


