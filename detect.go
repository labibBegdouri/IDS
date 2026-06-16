package main

// QUE ARP UDP TCP POUR IPV4 POUR LE MOMENT
func ratioSynAck(syn int, ack int) int {
	return syn - ack
}

func (ids *IDS) verifyAttackTCP(strIP string) {
	if ratioSynAck(ids.memory[strIP].syns, ids.memory[strIP].acks)+ratioSynAck(ids.precmemory[strIP].syns, ids.precmemory[strIP].acks) > NBRSCANSYN {
		ids.writelog("Is DDos attacking you", strIP)
		ids.memory[strIP].syns = 0
		ids.precmemory[strIP].syns = 0
	}
	if ids.memory[strIP].sshs+ids.precmemory[strIP].sshs > NBRSCANSSH {
		ids.writelog("Is bruteforcing you ssh Password", strIP)
		ids.memory[strIP].sshs = 0
		ids.precmemory[strIP].sshs = 0
	}
	if ids.memory[strIP].distinctPorts+ids.precmemory[strIP].distinctPorts > NBRSCANPorts {
		ids.writelog("Is scanning your ports", strIP)
		ids.memory[strIP].distinctPorts = 0
		ids.precmemory[strIP].distinctPorts = 0

	}
	if ids.memory[strIP].fins+ids.precmemory[strIP].fins > NBRSCANSYN {
		ids.writelog("Is spamming Fin flag", strIP)
		ids.memory[strIP].fins = 0
		ids.precmemory[strIP].fins = 0

	}
	if ids.memory[strIP].vide+ids.precmemory[strIP].vide > NBRSCANSYN {
		ids.writelog("Is spamming packets with no flags", strIP)
		ids.memory[strIP].vide = 0
		ids.precmemory[strIP].vide = 0

	}
	if ids.memory[strIP].finUrgPsh+ids.precmemory[strIP].finUrgPsh > NBRSCANSYN {
		ids.writelog("Is spamming packets with no flags", strIP)
		ids.memory[strIP].finUrgPsh = 0
		ids.precmemory[strIP].finUrgPsh = 0

	}

}

func (ids *IDS) verifyAttackARP(strIP string, Mac string) {
	if ids.memory[strIP].ArpMacResponse != "" && ids.memory[strIP].ArpMacResponse != Mac {

		ids.writelog("Is ARP poisining", strIP)
	}
}
