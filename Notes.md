Three ways to listen
#1 if we want to have a fully parsed packet (gopacket.Packet)
we use gopacket.NewPacketSource(handle, handle.LinkType()), it returns a channel that yeilds parsed NewPacketSource
but it slower

#2 hgopacket.NewPacketSource(handle, handle.LinkType()) (we can make the attribut NoCopy=false)
we read directly raw packets without parsing


## Decoding
by PacketSource.Packet/NewPacket we obtain a packetgo.Packet object (here packet)
# 1. we transform it to the layer object we want  by packet.Layer
# 2. we precise the type of the layer that we want by type assertion
At the end we have a struct of tha precised type with the necessary values



## Timeproblemes
time.NewPackets() prend bcp du temps ---> le seuil 2 secondes n'est pas respecté
La première itération ca prend bcp du temps ???






##  Cahier de charge 
détecter port scan 
Dos attaque --> bcp de SYN
SSh Brute force bcp de connection ssh (port 22)
