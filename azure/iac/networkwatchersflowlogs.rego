package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networkwatchers/flowlogs

#
# Azure Network Watcher NSG flow logs are disabled (259)
#

default netwatch_logs = null

azure_attribute_absence["netwatch_logs"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    not resource.properties.enabled
}

azure_issue["netwatch_logs"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    resource.properties.enabled != true
}

azure_issue["netwatch_logs"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    resource.properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled == false
}

netwatch_logs {
    lower(input.resources[_].type) == "microsoft.network/networkwatchers/flowlogs"
    not azure_issue["netwatch_logs"]
    not azure_attribute_absence["netwatch_logs"]
}

netwatch_logs = false {
    azure_issue["netwatch_logs"]
}

netwatch_logs = false {
    azure_attribute_absence["netwatch_logs"]
}

netwatch_logs_err = "Azure Network Watcher NSG flow logs are disabled" {
    azure_issue["netwatch_logs"]
}

netwatch_logs_miss_err = "NetWatcher FlowLog extension attribute retentionPolicy missing in the resource" {
    azure_attribute_absence["netwatch_logs"]
}

#
# Azure Network Watcher NSG flow logs retention is less than 90 days (260)
#

default netwatch_log_retention = null

azure_attribute_absence["netwatch_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    not resource.properties.retentionPolicy.enabled
}

azure_issue["netwatch_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    resource.properties.retentionPolicy.enabled != true
}

azure_issue["netwatch_log_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    to_number(resource.properties.retentionPolicy.days) < 90
}

netwatch_log_retention {
    lower(input.resources[_].type) == "microsoft.network/networkwatchers/flowlogs"
    not azure_issue["netwatch_log_retention"]
    not azure_attribute_absence["netwatch_log_retention"]
}

netwatch_log_retention = false {
    azure_issue["netwatch_log_retention"]
}

netwatch_log_retention = false {
    azure_attribute_absence["netwatch_log_retention"]
}

netwatch_log_retention_err = "Azure Network Watcher NSG flow logs retention is less than 90 days" {
    azure_issue["netwatch_log_retention"]
}

netwatch_log_retention_miss_err = "NetWatcher FlowLog extension attribute retentionPolicy missing in the resource" {
    azure_attribute_absence["netwatch_log_retention"]
}
