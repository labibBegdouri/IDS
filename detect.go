package main

import "fmt"

const (
	MaxSYNMinusAck       = 5000
	MaxFin               = 500
	MaxNull              = 500
	MaxXmas              = 500
	MaxSSHConnection     = 20
	MaxNbrPortsDistincts = 30
	MaxICMPS             = 6000
	MaxUDP               = 5000
	MaxDNSResMinusReq    = 4000
)

func (ids *IDS) verifyAttackTCP(strIP string) {
	mem := ids.memory[strIP]
	prec := ids.precMemory[strIP]

	if (mem.syns + prec.syns - mem.acks - prec.acks) > MaxSYNMinusAck {
		msg := fmt.Sprintf("[CRITICAL] TCP SYN Flood detecté. (Seuil: %d)", MaxSYNMinusAck)
		ids.writeLog(msg, strIP)
		ids.memory[strIP].syns = 0
		ids.precMemory[strIP].syns = 0
	}

	if (mem.sshs + prec.sshs) > MaxSSHConnection {
		msg := fmt.Sprintf("[WARNING] Tentative de SSH Brute Force. (%d tentatives)", mem.sshs+prec.sshs)
		ids.writeLog(msg, strIP)
		ids.memory[strIP].sshs = 0
		ids.precMemory[strIP].sshs = 0
	}

	if (mem.distinctPorts + prec.distinctPorts) > MaxNbrPortsDistincts {
		msg := fmt.Sprintf("[WARNING] Scan de ports détecté. (%d ports touchés)", mem.distinctPorts+prec.distinctPorts)
		ids.writeLog(msg, strIP)
		ids.memory[strIP].distinctPorts = 0
		ids.precMemory[strIP].distinctPorts = 0
	}

	if (mem.fins + prec.fins) > MaxFin {
		msg := "[WARNING] TCP FIN Scan/Flood détecté. (Flag FIN abusif)"
		ids.writeLog(msg, strIP)
		ids.memory[strIP].fins = 0
		ids.precMemory[strIP].fins = 0
	}

	if (mem.vide + prec.vide) > MaxNull {
		msg := "[WARNING] TCP Null Scan détecté. (Paquets sans flags TCP)"
		ids.writeLog(msg, strIP)
		ids.memory[strIP].vide = 0
		ids.precMemory[strIP].vide = 0
	}

	//  XMAS Scan ( FIN, URG, PSH)
	if (mem.finUrgPsh + prec.finUrgPsh) > MaxXmas {
		msg := "[WARNING] TCP XMAS Scan détecté. (Combinaison de flags anormale)"
		ids.writeLog(msg, strIP)
		ids.memory[strIP].finUrgPsh = 0
		ids.precMemory[strIP].finUrgPsh = 0
	}
}

func (ids *IDS) verifyAttackICMP(strIP string) {
	if (ids.memory[strIP].icmps + ids.precMemory[strIP].icmps) > MaxICMPS {
		ids.writeLog("[CRITICAL] ICMP Ping Flood détecté.", strIP)
		ids.memory[strIP].icmps = 0
		ids.precMemory[strIP].icmps = 0
	}
}

func (ids *IDS) verifyAttackUDP(strIP string) {
	if (ids.memory[strIP].udp + ids.precMemory[strIP].udp) > MaxUDP {
		ids.writeLog("[CRITICAL] UDP Flood détecté.", strIP)
		ids.memory[strIP].udp = 0
		ids.precMemory[strIP].udp = 0
	}

	//  DNS Amplification Attack
	if (ids.memory["ALL"].dnsResponse + ids.precMemory["ALL"].dnsResponse - ids.memory["ALL"].dnsRequests - ids.precMemory["ALL"].dnsRequests) > MaxDNSResMinusReq {
		ids.writeLog("[CRITICAL] Attaque DDoS par amplification DNS détectée (Réponses >> Requêtes).", "")
		ids.memory["ALL"].dnsResponse = 0
		ids.memory["ALL"].dnsRequests = 0
	}
}

func (ids *IDS) verifyAttackARP(strIP string, mac string) {
	if ids.memory[strIP].arpMacResponse != mac && ids.memory[strIP].arpMacResponse != "" {
		msg := "[CRITICAL] ARP Spoofing/Poisoning possible. Conflit de MAC pour l'IP."
		ids.writeLog(msg, strIP)
	}
}
