package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/virtualnetworks/virtualnetworkpeerings

#
# Azure virtual network peer is disconnected (284)
#

default vnet_peer = null

vnet_peer {
    lower(input.type) == "microsoft.network/virtualnetworks/virtualnetworkpeerings"
    lower(input.properties.peeringState) == "connected"
}

vnet_peer = false {
    lower(input.type) == "microsoft.network/virtualnetworks/virtualnetworkpeerings"
    lower(input.properties.peeringState) != "connected"
}

vnet_peer_err = "Azure virtual network peer is disconnected" {
    vnet_peer == false
}
