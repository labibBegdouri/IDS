package main

// QUE ARP UDP TCP POUR IPV4 POUR LE MOMENT
func ratioSynAck(syn int, ack int) int {
	return syn - ack
}

func (ids *IDS) verifyAttackTCP(strIP string) {
	if ratioSynAck(ids.memory[strIP].syns, ids.memory[strIP].acks)+ratioSynAck(ids.precmemory[strIP].syns, ids.precmemory[strIP].acks) > NBRSCANSYN {
		ids.writelog("Is DDos attacking you", strIP)
		ids.memory[strIP].syns = 0
	}
	if ids.memory[strIP].sshs+ids.precmemory[strIP].sshs > NBRSCANSSH {
		ids.writelog("Is bruteforcing you ssh Password", strIP)
		ids.memory[strIP].sshs = 0
	}
	if ids.memory[strIP].distinctPorts+ids.precmemory[strIP].distinctPorts > NBRSCANPorts {
		ids.writelog("Is scanning your ports", strIP)
		ids.memory[strIP].distinctPorts = 0

	}

}
