#
# PR-AZR-0075
#

package rule
default rulepass = true

# Azure virtual network peer is disconnected
# If virtual network peer is connected test will pass

rulepass = false {
    lower(input.type) == "microsoft.network/virtualnetworks"
    count(virtual_network_peer) >= 1
}

metadata := {
    "Policy Code": "PR-AZR-0075",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure virtual network peer is disconnected",
    "Policy Description": "Virtual network peering enables you to connect two Azure virtual networks so that the resources in these networks are directly connected.</br> </br> This policy identifies Azure virtual network peers that are disconnected. Typically, the disconnection happens when a peering configuration is deleted on one virtual network, and the other virtual network reports the peering status as disconnected.",
    "Resource Type": "microsoft.network/virtualnetworks",
    "Policy Help URL": "",
    "Resource Help URL": ""
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
