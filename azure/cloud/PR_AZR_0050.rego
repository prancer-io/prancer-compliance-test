#
# PR-AZR-0050
#

package rule
default rulepass = true

# Azure Network Watcher Network Security Group (NSG) flow logs are disabled
# If Network Watcher Network Security Group (NSG) flow logs are enabled test will pass


# url link not available for resource explorer

rulepass = false {
    lower(input.type) == "microsoft.network/networkwatchers"
    count(flowLogsSettings) >= 1
}

metadata := {
    "Policy Code": "PR-AZR-0050",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure Network Watcher Network Security Group (NSG) flow logs are disabled",
    "Policy Description": "This policy identifies Azure Network Security Groups (NSG) for which flow logs are disabled. To perform this check, enable this action on the Azure Service Principal: 'Microsoft.Network/networkWatchers/queryFlowLogStatus/action'.</br> </br> NSG flow logs, a feature of the Network Watcher app, enable you to view information about ingress and egress IP traffic through an NSG. The flow logs include information such as:</br> - Outbound and inbound flows on a per-rule basis.</br> - Network interface to which the flow applies.</br> - 5-tuple information about the flow (source/destination IP, source/destination port, protocol).</br> - Whether the traffic was allowed or denied.</br> </br> As a best practice, enable NSG flow logs to improve network visibility.",
    "Resource Type": "microsoft.network/networkwatchers",
    "Policy Help URL": "",
    "Resource Help URL": ""
}

# input.properties.enabled = false
# flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled = false

flowLogsSettings["flowLogsSettings_enabled"] {
    input.properties.enabled == false
}

flowLogsSettings["flowLogsSettings_networkWatcherFlowAnalyticsConfiguration_enabled"] {
    input.properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled == false
}
