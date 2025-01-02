import pydivert
import sys
import argparse
import json
import threading
# DÃ©finir les constantes des drapeaux TCP
TCP_FLAGS_FIN = 0x01
TCP_FLAGS_SYN = 0x02
TCP_FLAGS_RST = 0x04
TCP_FLAGS_PSH = 0x08
TCP_FLAGS_ACK = 0x10
TCP_FLAGS_URG = 0x20
TCP_FLAGS_ECE = 0x40
TCP_FLAGS_CWR = 0x80
TCP_FLAGS_NS = 0x100


# Ajoutez une structure pour stocker les ports UDP ouverts
open_udp_ports = set()
lock = threading.Lock()


def is_scan_packet(packet, allowed_ips_ports):
    """
    VÃ©rifie si le paquet fait partie d'une tentative de scan de port ou d'Ã©numÃ©ration.
    Exclut les paquets entrants destinÃ©s aux ports autorisÃ©s pour chaque IP spÃ©cifique.
    Bloque les paquets entrants qui ne respectent pas les rÃ¨gles dÃ©finies.
    """
    if packet.direction == pydivert.Direction.INBOUND:
        if packet.tcp:
            src_ip = packet.src_addr
            protocol = 'tcp'
            dst_port = packet.tcp.dst_port
            control_bits = packet.tcp.control_bits

            # Log dÃ©taillÃ© pour le dÃ©bogage
            print(f"Paquet TCP: src_ip={src_ip}, dst_port={dst_port}, control_bits={control_bits}")

            # Autoriser les paquets faisant partie de connexions Ã©tablies
            if control_bits & TCP_FLAGS_ACK:
                print("  -> Partie d'une connexion Ã©tablie")
                return False  # Autoriser le paquet

            # Autoriser via 'any'
            if ('any' in allowed_ips_ports and 
                protocol in allowed_ips_ports['any'] and 
                dst_port in allowed_ips_ports['any'][protocol]):
                print("  -> AutorisÃ© via 'any'")
                return False

            # Autoriser via IP spÃ©cifique
            if (src_ip in allowed_ips_ports and 
                protocol in allowed_ips_ports[src_ip] and 
                dst_port in allowed_ips_ports[src_ip][protocol]):
                print(f"  -> AutorisÃ© pour IP {src_ip}")
                return False

            # Bloquer le paquet si aucune condition ci-dessus n'est remplie
            print(f"  -> BloquÃ©: TCP port {dst_port} de {src_ip}")
            return True  # Bloquer le paquet

        elif packet.udp:
            src_ip = packet.src_addr
            protocol = 'udp'
            dst_port = packet.udp.dst_port
            src_port = packet.udp.src_port

            print(f"Paquet UDP: src_ip={src_ip}, src_port={src_port}, dst_port={dst_port}")

            with lock:
                if src_port in open_udp_ports:
                    print("  -> RÃ©ponse UDP autorisÃ©e")
                    return False  # Autoriser le paquet
                # Sinon, appliquer les rÃ¨gles existantes
                if ('any' in allowed_ips_ports and 
                    protocol in allowed_ips_ports['any'] and 
                    dst_port in allowed_ips_ports['any'][protocol]):
                    print("  -> AutorisÃ© via 'any'")
                    return False
                if (src_ip in allowed_ips_ports and 
                    protocol in allowed_ips_ports[src_ip] and 
                    dst_port in allowed_ips_ports[src_ip][protocol]):
                    print(f"  -> AutorisÃ© pour IP {src_ip}")
                    return False
                print(f"  -> BloquÃ©: UDP port {dst_port} de {src_ip}")
                return True
    elif packet.direction == pydivert.Direction.OUTBOUND:
        if packet.udp:
            dst_port = packet.udp.dst_port
            with lock:
                open_udp_ports.add(packet.udp.dst_port)
                # Optionnel : retirer les ports aprÃ¨s un dÃ©lai
    return False  # Autoriser tous les autres paquets

def anti_scan(allowed_ips_ports):
    """
    DÃ©marre un mÃ©canisme anti-scan et anti-Ã©numÃ©ration en utilisant pydivert.
    Le script bloque les paquets suspects en fonction des rÃ¨gles dÃ©finies.
    """
    print("DÃ©marrage du systÃ¨me anti-scan...", flush=True)

    # Affichage des configurations
    print("Configurations des IP et Ports AutorisÃ©s :", flush=True)
    for ip, protocols in allowed_ips_ports.items():
        for proto, ports in protocols.items():
            ports_display = ", ".join(map(str, sorted(ports))) if ports else "Aucun"
            print(f"  IP: {ip} -> {proto.upper()} Ports: {ports_display}", flush=True)

    # Filtrer uniquement les paquets inbound TCP/UDP
    with pydivert.WinDivert("ip and (tcp or udp)") as w:
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
    parser = argparse.ArgumentParser(description="Script Anti-scan utilisant pydivert avec configuration par IP-Protocole-Port.")
    parser.add_argument('--config', type=str, required=True,
                        help='Configuration JSON des adresses IP et des ports autorisÃ©s par protocole.')
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