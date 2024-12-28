import pydivert
import sys
import argparse
import json

# Définir les constantes des drapeaux TCP
TCP_FLAGS_FIN = 0x01
TCP_FLAGS_SYN = 0x02
TCP_FLAGS_RST = 0x04
TCP_FLAGS_PSH = 0x08
TCP_FLAGS_ACK = 0x10
TCP_FLAGS_URG = 0x20
TCP_FLAGS_ECE = 0x40
TCP_FLAGS_CWR = 0x80
TCP_FLAGS_NS = 0x100

def is_scan_packet(packet, allowed_ips_ports):
    """
    Vérifie si le paquet fait partie d'une tentative de scan de port ou d'énumération.
    Exclut les paquets entrants destinés aux ports autorisés pour chaque IP spécifique.
    Bloque les paquets entrants qui ne respectent pas les règles définies.
    """
    if packet.direction == pydivert.Direction.INBOUND:
        if packet.tcp:
            src_ip = packet.src_addr
            protocol = 'tcp'
            dst_port = packet.tcp.dst_port
            control_bits = packet.tcp.control_bits

            # Log détaillé pour le débogage
            print(f"Paquet TCP: src_ip={src_ip}, dst_port={dst_port}, control_bits={control_bits}")

            # Autoriser les paquets faisant partie de connexions établies
            if control_bits & TCP_FLAGS_ACK:
                print("  -> Partie d'une connexion établie")
                return False  # Autoriser le paquet

            # Autoriser via 'any'
            if ('any' in allowed_ips_ports and 
                protocol in allowed_ips_ports['any'] and 
                dst_port in allowed_ips_ports['any'][protocol]):
                print("  -> Autorisé via 'any'")
                return False

            # Autoriser via IP spécifique
            if (src_ip in allowed_ips_ports and 
                protocol in allowed_ips_ports[src_ip] and 
                dst_port in allowed_ips_ports[src_ip][protocol]):
                print(f"  -> Autorisé pour IP {src_ip}")
                return False

            # Bloquer le paquet si aucune condition ci-dessus n'est remplie
            print(f"  -> Bloqué: TCP port {dst_port} de {src_ip}")
            return True  # Bloquer le paquet

        elif packet.udp:
            src_ip = packet.src_addr
            protocol = 'udp'
            dst_port = packet.udp.dst_port

            # Log détaillé pour le débogage
            print(f"Paquet UDP: src_ip={src_ip}, dst_port={dst_port}")

            # Autoriser via 'any'
            if ('any' in allowed_ips_ports and 
                protocol in allowed_ips_ports['any'] and 
                dst_port in allowed_ips_ports['any'][protocol]):
                print("  -> Autorisé via 'any'")
                return False  # Autoriser le paquet

            # Autoriser via IP spécifique
            if (src_ip in allowed_ips_ports and 
                protocol in allowed_ips_ports[src_ip] and 
                dst_port in allowed_ips_ports[src_ip][protocol]):
                print(f"  -> Autorisé pour IP {src_ip}")
                return False  # Autoriser le paquet

            # Bloquer le paquet si aucune condition ci-dessus n'est remplie
            print(f"  -> Bloqué: UDP port {dst_port} de {src_ip}")
            return True  # Bloquer le paquet

    return False  # Autoriser tous les autres paquets

def anti_scan(allowed_ips_ports):
    """
    Démarre un mécanisme anti-scan et anti-énumération en utilisant pydivert.
    Le script bloque les paquets suspects en fonction des règles définies.
    """
    print("Démarrage du système anti-scan...", flush=True)

    # Affichage des configurations
    print("Configurations des IP et Ports Autorisés :", flush=True)
    for ip, protocols in allowed_ips_ports.items():
        for proto, ports in protocols.items():
            ports_display = ", ".join(map(str, sorted(ports))) if ports else "Aucun"
            print(f"  IP: {ip} -> {proto.upper()} Ports: {ports_display}", flush=True)

    # Filtrer uniquement les paquets inbound TCP/UDP
    with pydivert.WinDivert("ip and (tcp or udp)") as w:
        for packet in w:
            try:
                # Vérifier si le paquet est suspect
                if is_scan_packet(packet, allowed_ips_ports):
                    print(f"Paquet suspect bloqué : {packet}", flush=True)
                    continue  # Bloquer le paquet en ne le réinjectant pas
                else:
                    w.send(packet)  # Réinjecter les paquets légitimes
            except Exception as e:
                print(f"Erreur lors du traitement du paquet : {e}", flush=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script Anti-scan utilisant pydivert avec configuration par IP-Protocole-Port.")
    parser.add_argument('--config', type=str, required=True,
                        help='Configuration JSON des adresses IP et des ports autorisés par protocole.')
    args = parser.parse_args()

    try:
        # Charger la configuration JSON
        allowed_ips_ports = json.loads(args.config)
        # Convertir les listes de ports en ensembles pour une recherche rapide
        for ip in allowed_ips_ports:
            for protocol in allowed_ips_ports[ip]:
                allowed_ips_ports[ip][protocol] = set(map(int, allowed_ips_ports[ip][protocol]))
    except json.JSONDecodeError:
        print("Erreur: La configuration JSON est invalide.", flush=True)
        sys.exit(1)
    except Exception as e:
        print(f"Erreur lors du chargement de la configuration: {e}", flush=True)
        sys.exit(1)

    anti_scan(allowed_ips_ports)
