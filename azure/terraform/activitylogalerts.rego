package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_activity_log_alert

#
# PR-AZR-0090-TRF
#

default azure_monitor_activity_log_alert_enabled = null

# by default alert get enabled if not exist.
azure_attribute_absence["azure_monitor_activity_log_alert_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    not resource.properties.enabled
}

azure_issue["azure_monitor_activity_log_alert_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    resource.properties.enabled != true
}

azure_monitor_activity_log_alert_enabled {
    azure_attribute_absence["azure_monitor_activity_log_alert_enabled"]
}

azure_monitor_activity_log_alert_enabled {
    lower(input.resources[_].type) == "azurerm_monitor_activity_log_alert"
    not azure_attribute_absence["azure_monitor_activity_log_alert_enabled"]
    not azure_issue["azure_monitor_activity_log_alert_enabled"]
}

azure_monitor_activity_log_alert_enabled = false {
    azure_issue["azure_monitor_activity_log_alert_enabled"]
}

azure_monitor_activity_log_alert_enabled_err = "azurerm_monitor_activity_log_alert property 'enabled' is missing from the resource. Please set the value to 'true' after property addition." {
    azure_issue["azure_monitor_activity_log_alert_enabled"]
}

azure_monitor_activity_log_alert_enabled_metadata := {
    "Policy Code": "PR-AZR-0090-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Activity log alerts should be enabled",
    "Policy Description": "Activity log alerts are alerts that activate when a new activity log event occurs that matches the conditions specified in the alert. Based on the order and volume of the events recorded in Azure activity log, the alert rule will fire. Enabling Activity log alerts will allow Azure to send you emails about any high severity alerts in your environment. This will make sure that you are aware of any security issues and take prompt actions to mitigate the risks.",
    "Resource Type": "azurerm_monitor_activity_log_alert",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_activity_log_alert"
}