package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/virtualnetworks/virtualnetworkpeerings

#
# PR-AZR-0075-ARM
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

vnet_peer_metadata := {
    "Policy Code": "PR-AZR-0075-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure virtual network peer is disconnected",
    "Policy Description": "Virtual network peering enables you to connect two Azure virtual networks so that the resources in these networks are directly connected._x005F_x000D_ _x005F_x000D_ This policy identifies Azure virtual network peers that are disconnected. Typically, the disconnection happens when a peering configuration is deleted on one virtual network, and the other virtual network reports the peering status as disconnected.",
    "Compliance": [],
    "Resource Type": "microsoft.network/virtualnetworks/virtualnetworkpeerings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/virtualnetworks/virtualnetworkpeerings"
}
