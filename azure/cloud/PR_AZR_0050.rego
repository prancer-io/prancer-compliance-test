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

# input.properties.enabled = false
# flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled = false

flowLogsSettings["flowLogsSettings_enabled"] {
   input.properties.enabled == false
}

flowLogsSettings["flowLogsSettings_networkWatcherFlowAnalyticsConfiguration_enabled"] {
   input.properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled == false
}
