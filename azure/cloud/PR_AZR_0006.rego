#
# PR-AZR-0006
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.containerservice/2020-04-01/managedclusters

rulepass {
    lower(input.type) == "microsoft.containerregistry/registries/webhooks"
    input.properties.networkProfile.networkPlugin == "azure"
}

metadata := {
    "Policy Code": "PR-AZR-0006",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure AKS cluster Azure CNI networking not enabled",
    "Policy Description": "Azure CNI provides the following features over kubenet networking:_x005F_x000D_ _x005F_x000D_ - Every pod in the cluster is assigned an IP address in the virtual network. The pods can directly communicate with other pods in the cluster, and other nodes in the virtual network._x005F_x000D_ - Pods in a subnet that have service endpoints enabled can securely connect to Azure services, such as Azure Storage and SQL DB._x005F_x000D_ - You can create user-defined routes (UDR) to route traffic from pods to a Network Virtual Appliance._x005F_x000D_ - Support for Network Policies securing communication between pods._x005F_x000D_ _x005F_x000D_ This policy checks your AKS cluster for the Azure CNI network plugin and generates an alert if not found.",
    "Compliance": [],
    "Resource Type": "microsoft.containerregistry/registries/webhooks",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.containerservice/2020-04-01/managedclusters"
}
