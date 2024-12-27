import pydivert
import sys
import argparse
import json

def is_scan_packet(packet, allowed_ips_ports):
    """
    VÃ©rifie si le paquet fait partie d'une tentative de scan de port ou d'Ã©numÃ©ration.
    Exclut les paquets entrants destinÃ©s aux ports autorisÃ©s pour chaque IP spÃ©cifique.
    Bloque les paquets entrants qui ne respectent pas les rÃ¨gles dÃ©finies.
    """
    if packet.direction == pydivert.Direction.INBOUND:
        if packet.tcp:
            src_ip = packet.src_addr
            dst_port = packet.dst_port

            # VÃ©rifier si l'IP source est autorisÃ©e
            if src_ip in allowed_ips_ports:
                # VÃ©rifier si le port de destination est autorisÃ© pour cette IP
                if dst_port in allowed_ips_ports[src_ip]:
                    return False  # Autoriser le paquet
                else:
                    return True   # Bloquer le paquet
            else:
                return True  # Bloquer le paquet si l'IP n'est pas autorisÃ©e
    return False  # Autoriser les paquets non inbound ou non TCP/IP

def anti_scan(allowed_ips_ports):
    """
    DÃ©marre un mÃ©canisme anti-scan et anti-Ã©numÃ©ration en utilisant pydivert.
    Le script bloque les paquets suspects en fonction des rÃ¨gles dÃ©finies.
    """
    print("DÃ©marrage du systÃ¨me anti-scan...", flush=True)

    # Affichage des configurations
    print("Configurations des IP et Ports AutorisÃ©s :", flush=True)
    for ip, ports in allowed_ips_ports.items():
        print(f"  IP: {ip} -> Ports: {sorted(ports)}", flush=True)

    # Ouvrir une session WinDivert pour tout le trafic TCP/IP
    with pydivert.WinDivert("ip and tcp") as w:
        for packet in w:
            try:
                # VÃ©rifier si le paquet est suspect
                if is_scan_packet(packet, allowed_ips_ports):
                    print(f"Paquet suspect bloquÃ© : {packet}", flush=True)
                    continue  # Bloquer le paquet en ne le rÃ©injectant pas
                else:
                    w.send(packet)  # RÃ©injecter les paquets lÃ©gitimes
            except Exception as e:
                print(f"Erreur lors du traitement du paquet : {e}", flush=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script Anti-scan utilisant pydivert avec configuration par IP-Port.")
    parser.add_argument('--config', type=str, required=True,
                        help='Configuration JSON des adresses IP et des ports autorisÃ©s.')
    args = parser.parse_args()

    try:
        # Charger la configuration JSON
        allowed_ips_ports = json.loads(args.config)
        # Convertir les listes de ports en ensembles pour une recherche rapide
        for ip in allowed_ips_ports:
            allowed_ips_ports[ip] = set(map(int, allowed_ips_ports[ip]))
    except json.JSONDecodeError:
        print("Erreur: La configuration JSON est invalide.", flush=True)
        sys.exit(1)
    except Exception as e:
        print(f"Erreur lors du chargement de la configuration: {e}", flush=True)
        sys.exit(1)

    anti_scan(allowed_ips_ports)