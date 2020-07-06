package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networkwatchers/flowlogs

#
# Azure Network Watcher NSG flow logs are disabled (259)
#

default netwatch_logs = null

netwatch_logs {
    lower(input.type) == "microsoft.network/networkwatchers/flowlogs"
    input.properties.enabled == true
    input.properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled == true
}

netwatch_logs = false {
    lower(input.type) == "microsoft.network/networkwatchers/flowlogs"
    input.properties.enabled == false
}

netwatch_logs = false {
    lower(input.type) == "microsoft.network/networkwatchers/flowlogs"
    input.properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled == false
}

netwatch_logs_err = "Azure Network Watcher NSG flow logs are disabled" {
    netwatch_logs == false
}

#
# Azure Network Watcher NSG flow logs retention is less than 90 days (260)
#

default netwatch_log_retention = null

netwatch_log_retention {
    lower(input.type) == "microsoft.network/networkwatchers/flowlogs"
    input.properties.retentionPolicy.enabled == true
    to_number(input.properties.retentionPolicy.days) >= 90
}

netwatch_log_retention = false {
    lower(input.type) == "microsoft.network/networkwatchers/flowlogs"
    input.properties.retentionPolicy.enabled == false
}

netwatch_log_retention = false {
    lower(input.type) == "microsoft.network/networkwatchers/flowlogs"
    to_number(input.properties.retentionPolicy.days) < 90
}

netwatch_log_retention_err = "Azure Network Watcher NSG flow logs retention is less than 90 days" {
    netwatch_log_retention == false
}
