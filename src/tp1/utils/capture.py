from collections import defaultdict

from scapy.all import sniff, ARP, TCP, UDP, ICMP, IP, DNS, Raw

from tp1.utils.lib import choose_interface
from tp1.utils.config import logger

# SQL keywords to detect injection attempts
SQL_KEYWORDS = [b"SELECT", b"INSERT", b"UPDATE", b"DELETE", b"DROP", b"UNION", b"CREATE", b"ALTER"]

CAPTURE_COUNT = 100
CAPTURE_TIMEOUT = 30
PORT_SCAN_THRESHOLD = 15


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.packets = []
        self.protocol_counts: dict[str, int] = defaultdict(int)
        self.alerts: list[dict] = []
        self.summary = ""

    def _identify_protocol(self, pkt) -> str:
        if pkt.haslayer(ARP):
            return "ARP"
        if pkt.haslayer(DNS):
            return "DNS"
        if pkt.haslayer(TCP):
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load).upper()
                if any(kw in payload for kw in SQL_KEYWORDS):
                    return "SQL_INJECT"
            return "TCP"
        if pkt.haslayer(UDP):
            return "UDP"
        if pkt.haslayer(ICMP):
            return "ICMP"
        if pkt.haslayer(IP):
            return "IP"
        return "Other"

    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface
        """
        logger.info(f"Capture traffic from interface {self.interface}")
        logger.info(f"Capture de {CAPTURE_COUNT} paquets (timeout {CAPTURE_TIMEOUT}s)...")
        self.packets = sniff(iface=self.interface, count=CAPTURE_COUNT, timeout=CAPTURE_TIMEOUT)
        logger.info(f"{len(self.packets)} paquets capturés")

        for pkt in self.packets:
            proto = self._identify_protocol(pkt)
            self.protocol_counts[proto] += 1

    def sort_network_protocols(self) -> str:
        """
        Sort and return all captured network protocols
        """
        sorted_protos = sorted(self.protocol_counts.items(), key=lambda x: x[1], reverse=True)
        return "\n".join(f"{proto}: {count}" for proto, count in sorted_protos)

    def get_all_protocols(self) -> str:
        """
        Return all protocols captured with total packets number
        """
        return "\n".join(f"{proto}: {count}" for proto, count in self.protocol_counts.items())

    def _detect_arp_spoofing(self) -> list:
        """Detect ARP spoofing: same IP answered by different MACs"""
        alerts = []
        ip_mac_map = {}
        for pkt in self.packets:
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
                ip = pkt[ARP].psrc
                mac = pkt[ARP].hwsrc
                if ip in ip_mac_map and ip_mac_map[ip] != mac:
                    alerts.append({
                        "type": "ARP Spoofing",
                        "protocol": "ARP",
                        "src_ip": ip,
                        "src_mac": mac,
                        "detail": f"IP {ip} revendiquee par {mac} (precedemment {ip_mac_map[ip]})",
                    })
                ip_mac_map[ip] = mac
        return alerts

    def _detect_sql_injection(self) -> list:
        """Detect SQL injection attempts in TCP payload"""
        alerts = []
        for pkt in self.packets:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):
                payload = bytes(pkt[Raw].load).upper()
                if any(kw in payload for kw in SQL_KEYWORDS):
                    src_ip = pkt[IP].src
                    src_mac = pkt.src if hasattr(pkt, "src") else "inconnu"
                    alerts.append({
                        "type": "SQL Injection",
                        "protocol": "TCP",
                        "src_ip": src_ip,
                        "src_mac": src_mac,
                        "detail": f"Mots-cles SQL detectes dans le payload depuis {src_ip}",
                    })
        return alerts

    def _detect_port_scan(self) -> list:
        """Detect port scan: many SYN packets to different ports from same source"""
        alerts = []
        src_ports: dict[str, set] = defaultdict(set)
        for pkt in self.packets:
            if pkt.haslayer(TCP) and pkt.haslayer(IP) and pkt[TCP].flags == "S":
                src_ports[pkt[IP].src].add(pkt[TCP].dport)
        for src_ip, ports in src_ports.items():
            if len(ports) >= PORT_SCAN_THRESHOLD:
                alerts.append({
                    "type": "Port Scan",
                    "protocol": "TCP",
                    "src_ip": src_ip,
                    "src_mac": "inconnu",
                    "detail": f"Scan de ports depuis {src_ip} ({len(ports)} ports uniques)",
                })
        return alerts

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        Si un trafic est illégitime (exemple : Injection SQL, ARP
        Spoofing, etc)
        a. Noter la tentative d'attaque.
        b. Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c. (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon afficher que tout va bien
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

        self.alerts = []
        self.alerts.extend(self._detect_arp_spoofing())
        self.alerts.extend(self._detect_sql_injection())
        self.alerts.extend(self._detect_port_scan())

        if self.alerts:
            for alert in self.alerts:
                logger.warning(f"[ATTAQUE] {alert['type']} - {alert['detail']}")
        else:
            logger.info("Analyse terminée : aucune menace détectée, tout va bien.")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        lines = [
            f"Total de paquets capturés : {len(self.packets)}",
            f"Protocoles détectés : {len(self.protocol_counts)}",
        ]
        if self.alerts:
            lines.append(f"\nALERTES - {len(self.alerts)} menace(s) detectee(s) :")
            for a in self.alerts:
                lines.append(
                    f"  [{a['type']}] {a['detail']}"
                    f" | Protocole: {a['protocol']}"
                    f" | IP: {a['src_ip']}"
                    f" | MAC: {a['src_mac']}"
                )
        else:
            lines.append("\nTout va bien - aucune menace detectee dans le trafic capture.")
        return "\n".join(lines)
