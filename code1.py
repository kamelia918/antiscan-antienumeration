import socket
import time
import pydivert
import subprocess

# Liste des adresses IP suspectes
suspect_ips = {}
THRESHOLD = 10  # Nombre de connexions avant de considérer une IP comme suspecte
TARPIT_DELAY = 5  # Temps de retard en secondes

# Fonction pour gérer le tarpit
def tarpit(ip):
    print(f"Tarpit activé pour {ip}")
    time.sleep(TARPIT_DELAY)

# Fonction pour bloquer une adresse IP
def block_ip(ip):
    print(f"Blocage de l'adresse IP {ip}")
    try:
        subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=Block_{ip}", "dir=in", "action=block", f"remoteip={ip}"], check=True)
        subprocess.run(["ping", "-n", "1", ip], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Erreur lors du blocage ou du ping de {ip}: {e}")

# Capture de paquets avec WinDivert
with pydivert.WinDivert("true") as w:
    print("Capture des paquets en cours...")
    for packet in w:
        try:
            if packet.is_inbound:
                src_ip = packet.src_addr
                dst_port = packet.dst_port

                # Détection de scans TCP SYN
                if packet.tcp and packet.tcp.syn:
                    print(f"SYN reçu de {src_ip} vers le port {dst_port}")
                    suspect_ips[src_ip] = suspect_ips.get(src_ip, 0) + 1

                # Détection de scans TCP FIN
                elif packet.tcp and packet.tcp.fin:
                    print(f"FIN reçu de {src_ip} vers le port {dst_port}")
                    suspect_ips[src_ip] = suspect_ips.get(src_ip, 0) + 1

                # Détection de scans TCP XMAS
                elif packet.tcp and packet.tcp.psh and packet.tcp.urg and packet.tcp.fin:
                    print(f"XMAS Scan détecté de {src_ip} vers le port {dst_port}")
                    suspect_ips[src_ip] = suspect_ips.get(src_ip, 0) + 1

                # Détection de scans UDP
                elif packet.udp:
                    print(f"UDP reçu de {src_ip} vers le port {dst_port}")
                    suspect_ips[src_ip] = suspect_ips.get(src_ip, 0) + 1

                # Si une IP dépasse le seuil, activer le tarpit et bloquer l'adresse
                if suspect_ips.get(src_ip, 0) >= THRESHOLD:
                    tarpit(src_ip)
                    block_ip(src_ip)
                    suspect_ips[src_ip] = 0  # Réinitialiser le compteur après tarpit et blocage

            # Réinjection du paquet pour éviter d'interrompre le trafic légitime
            w.send(packet)
        except Exception as e:
            print(f"Erreur: {e}")