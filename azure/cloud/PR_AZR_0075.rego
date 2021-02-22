#
# PR-AZR-0075
#

package rule
default rulepass = true

# Azure virtual network peer is disconnected
# If virtual network peer is connected test will pass

rulepass = false {    
   input.type == "Microsoft.Network/virtualNetworks"
   count(virtual_network_peer) >= 1
}

# flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled

virtual_network_peer["virtual_network_peer_not_connected"] {
   peering := input.properties.virtualNetworkPeerings[_]
   peering.properties.peeringState != "Connected"
}

virtual_network_peer["virtual_network_peering_is_empty"] {
   count(input.properties.virtualNetworkPeerings) == 0
}

virtual_network_peer["virtual_network_peer_provisioning_state"] {
   peering := input.properties.virtualNetworkPeerings[_]
   peering.properties.provisioningState != "Succeeded"
}
