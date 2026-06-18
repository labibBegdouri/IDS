package main

// QUE ARP UDP TCP POUR IPV4 POUR LE MOMENT

func (ids *IDS) verifyAttackTCP(strIP string) {
	if (ids.memory[strIP].syns - ids.memory[strIP].acks + -ids.precMemory[strIP].acks) > NBRSCANSYN {
		ids.writeLog("Is DDos attacking you", strIP)
		ids.memory[strIP].syns = 0
		ids.precMemory[strIP].syns = 0
	}
	if ids.memory[strIP].sshs+ids.precMemory[strIP].sshs > NBRSCANSSH {
		ids.writeLog("Is bruteforcing you ssh Password", strIP)
		ids.memory[strIP].sshs = 0
		ids.precMemory[strIP].sshs = 0
	}
	if ids.memory[strIP].distinctPorts+ids.precMemory[strIP].distinctPorts > NBRSCANPorts {
		ids.writeLog("Is scanning your ports", strIP)
		ids.memory[strIP].distinctPorts = 0
		ids.precMemory[strIP].distinctPorts = 0

	}
	if ids.memory[strIP].fins+ids.precMemory[strIP].fins > NBRSCANSYN {
		ids.writeLog("Is spamming Fin flag", strIP)
		ids.memory[strIP].fins = 0
		ids.precMemory[strIP].fins = 0

	}
	if ids.memory[strIP].vide+ids.precMemory[strIP].vide > NBRSCANSYN {
		ids.writeLog("Is spamming packets with no flags", strIP)
		ids.memory[strIP].vide = 0
		ids.precMemory[strIP].vide = 0

	}
	if ids.memory[strIP].finUrgPsh+ids.precMemory[strIP].finUrgPsh > NBRSCANSYN {
		ids.writeLog("Is spamming packets with no flags", strIP)
		ids.memory[strIP].finUrgPsh = 0
		ids.precMemory[strIP].finUrgPsh = 0

	}

}

func (ids *IDS) verifyAttackUDP(strIP string) {
	if ids.memory[strIP].udp+ids.precMemory[strIP].udp > NBRSCANICMP {
		ids.writeLog("Is Creating an UDP FLOOD ", strIP)
		ids.memory[strIP].udp = 0
	}
	if ids.memory[strIP].dnsResponse-ids.memory[strIP].dnsRequests > NBRSCANSYN {
		ids.writeLog("Someone Is Ddos attacking you (DNS amplification) ", "")

	}
}

func (ids *IDS) verifyAttackARP(strIP string, Mac string) {
	if ids.memory[strIP].arpMacResponse != Mac {
		ids.writeLog("Is ARP poisening or being poisened", strIP)
	}
}
