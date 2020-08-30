package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/virtualnetworks/virtualnetworkpeerings

#
# Azure virtual network peer is disconnected (284)
#

default vnet_peer = null

azure_attribute_absence["vnet_peer"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/virtualnetworks/virtualnetworkpeerings"
    not resource.properties.peeringState
}

azure_issue["vnet_peer"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/virtualnetworks/virtualnetworkpeerings"
    lower(resource.properties.peeringState) != "connected"
}

vnet_peer {
    lower(input.resources[_].type) == "microsoft.network/virtualnetworks/virtualnetworkpeerings"
    not azure_issue["vnet_peer"]
    not azure_attribute_absence["vnet_peer"]
}

vnet_peer = false {
    azure_issue["vnet_peer"]
}

vnet_peer = false {
    azure_attribute_absence["vnet_peer"]
}

vnet_peer_err = "Azure virtual network peer is disconnected" {
    azure_issue["vnet_peer"]
}

vnet_peer_miss_err = "Attribute peeringState missing in the resource" {
    azure_attribute_absence["vnet_peer"]
}
