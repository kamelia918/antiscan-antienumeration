import time
import pydivert
from collections import defaultdict

# Liste des adresses IP suspectes et leurs ports scannés
suspect_ips = {}
ports_scanned = defaultdict(set)  # Enregistre les ports scannés par IP
THRESHOLD = 10  # Nombre de connexions avant de considérer une IP comme suspecte
TARPIT_DELAY = 5  # Temps de retard en secondes
BLOCK_DURATION = 60  # Temps de blocage en secondes

# Fonction pour gérer le tarpit
def tarpit(ip):
    print(f"Tarpit activé pour {ip}")
    time.sleep(TARPIT_DELAY)

# Fonction pour bloquer une adresse IP temporairement
def block_ip(w, ip):
    print(f"Blocage temporaire de l'adresse IP {ip}")
    
    # Bloquer tous les paquets entrants et sortants de cette IP, sauf ICMP
    while True:
        for packet in w:
            try:
                # Si le paquet est un ICMP (ping), on ne le bloque pas
                if packet.icmp:
                    if packet.src_addr == ip or packet.dst_addr == ip:
                        w.send(packet)  # Réinjecte le paquet ICMP sans modification
                    continue  # Ignore le reste du traitement pour les paquets ICMP

                # Si ce n'est pas un ICMP, on bloque tous les autres paquets
                if packet.src_addr == ip or packet.dst_addr == ip:
                    print(f"Blocage du paquet {packet} de {ip}")
                    continue  # Ignore le paquet et ne le renvoie pas
                else:
                    w.send(packet)  # Réinjecte les autres paquets normalement

            except Exception as e:
                print(f"Erreur lors du traitement du paquet: {e}")
        
        # Après un certain délai, on arrête de bloquer l'IP
        time.sleep(BLOCK_DURATION)
        break

# Capture de paquets avec WinDivert
with pydivert.WinDivert("true") as w:
    print("Capture des paquets en cours...")
    for packet in w:
        try:
            if packet.is_inbound:
                src_ip = packet.src_addr
                dst_port = packet.dst_port

                # Si le paquet est un ICMP (ping), on ignore le blocage
                if packet.icmp:
                    print(f"ICMP (ping) reçu de {src_ip}, pas de blocage")
                    w.send(packet)  # Réinjecte le paquet ICMP sans modification
                    continue  # Ignore le reste du traitement pour les paquets ICMP

                # Détection de scans TCP SYN
                if packet.tcp and packet.tcp.syn:
                    print(f"SYN reçu de {src_ip} vers le port {dst_port}")
                    ports_scanned[src_ip].add(dst_port)
                    suspect_ips[src_ip] = suspect_ips.get(src_ip, 0) + 1

                # Détection de scans TCP FIN
                elif packet.tcp and packet.tcp.fin:
                    print(f"FIN reçu de {src_ip} vers le port {dst_port}")
                    ports_scanned[src_ip].add(dst_port)
                    suspect_ips[src_ip] = suspect_ips.get(src_ip, 0) + 1

                # Détection de scans TCP XMAS
                elif packet.tcp and packet.tcp.psh and packet.tcp.urg and packet.tcp.fin:
                    print(f"XMAS Scan détecté de {src_ip} vers le port {dst_port}")
                    ports_scanned[src_ip].add(dst_port)
                    suspect_ips[src_ip] = suspect_ips.get(src_ip, 0) + 1

                # Détection de scans UDP
                elif packet.udp:
                    print(f"UDP reçu de {src_ip} vers le port {dst_port}")
                    ports_scanned[src_ip].add(dst_port)
                    suspect_ips[src_ip] = suspect_ips.get(src_ip, 0) + 1

                # Bloquer immédiatement si un seul port est scanné plusieurs fois
                if len(ports_scanned[src_ip]) > 0 and suspect_ips.get(src_ip, 0) >= 1:
                    print(f"Scan unique détecté de {src_ip} sur les ports: {ports_scanned[src_ip]}")
                    tarpit(src_ip)
                    block_ip(w, src_ip)
                    ports_scanned[src_ip].clear()
                    suspect_ips[src_ip] = 0

            # Ne pas réinjecter les paquets suspects pour bloquer les résultats de scan
            else:
                w.send(packet)
        except Exception as e:
            print(f"Erreur: {e}")
