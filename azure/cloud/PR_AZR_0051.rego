#
# PR-AZR-0051
#

package rule
default rulepass = false

# Azure Network Watcher Network Security Group (NSG) flow logs retention is less than 90 days
# If NSG flow logs retention is 90 more than 90 days test will pass

rulepass = true {
    lower(input.type) == "microsoft.network/networkwatchers"
    count(nsg_retentionPolicy) == 2
}

metadata := {
    "Policy Code": "PR-AZR-0051",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure Network Watcher Network Security Group (NSG) flow logs retention is less than 90 days",
    "Policy Description": "This policy identifies Azure Network Security Groups (NSG) for which flow logs retention period is 90 days or less. To perform this check, enable this action on the Azure Service Principal: 'Microsoft.Network/networkWatchers/queryFlowLogStatus/action'._x005F_x000D_ _x005F_x000D_ NSG flow logs, a feature of the Network Watcher app, enable you to view information about ingress and egress IP traffic through an NSG. The flow logs include information such as:_x005F_x000D_ - Outbound and inbound flows on a per-rule basis._x005F_x000D_ - Network interface to which the flow applies._x005F_x000D_ - 5-tuple information about the flow (source/destination IP, source/destination port, protocol)._x005F_x000D_ - Whether the traffic was allowed or denied._x005F_x000D_ _x005F_x000D_ As a best practice, enable NSG flow logs and set the log retention period to at least 90 days.",
    "Compliance": [],
    "Resource Type": "microsoft.network/networkwatchers",
    "Policy Help URL": "",
    "Resource Help URL": ""
}

# properties.retentionPolicy.enabled
# properties.retentionPolicy.days >= 90

nsg_retentionPolicy["retentionPolicy_enabled"] {
    input.properties.retentionPolicy.enabled == true
}

nsg_retentionPolicy["retentionPolicy_day_90"] {
    input.properties.retentionPolicy.days >= 90
}
