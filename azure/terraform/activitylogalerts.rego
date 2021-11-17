package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_activity_log_alert

#
# PR-AZR-TRF-MNT-001
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
    lower(input.resources[_].type) == "azurerm_monitor_activity_log_alert"
    azure_attribute_absence["azure_monitor_activity_log_alert_enabled"]
    not azure_issue["azure_monitor_activity_log_alert_enabled"]
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
    "Policy Code": "PR-AZR-TRF-MNT-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Activity log alerts should be enabled",
    "Policy Description": "Activity log alerts are alerts that activate when a new activity log event occurs that matches the conditions specified in the alert. Based on the order and volume of the events recorded in Azure activity log, the alert rule will fire. Enabling Activity log alerts will allow Azure to send you emails about any high severity alerts in your environment. This will make sure that you are aware of any security issues and take prompt actions to mitigate the risks.",
    "Resource Type": "azurerm_monitor_activity_log_alert",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_activity_log_alert"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile

# Manages a Log Profile. A Log Profile configures how Activity Logs are exported.
# It's only possible to configure one Log Profile per Subscription. If you are trying to create more than one Log Profile, an error with StatusCode=409 will occur.
# PR-AZR-TRF-MNT-009
#

default azure_monitor_log_profile_retention = null

azure_attribute_absence["azure_monitor_log_profile_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_log_profile"
    not resource.properties.retention_policy
}

azure_attribute_absence["azure_monitor_log_profile_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_log_profile"
    retention_policy := resource.properties.retention_policy[_]
    not retention_policy.days
}

azure_issue["azure_monitor_log_profile_retention"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_log_profile"
    retention_policy := resource.properties.retention_policy[_]
    to_number(retention_policy.days) < 365
}

azure_monitor_log_profile_retention = false {
    azure_attribute_absence["azure_monitor_log_profile_retention"]
}

azure_monitor_log_profile_retention {
    lower(input.resources[_].type) == "azurerm_monitor_log_profile"
    not azure_attribute_absence["azure_monitor_log_profile_retention"]
    not azure_issue["azure_monitor_log_profile_retention"]
}

azure_monitor_log_profile_retention = false {
    azure_issue["azure_monitor_log_profile_retention"]
}

azure_monitor_log_profile_retention_err = "azurerm_monitor_log_profile property 'retention_policy.days' is missing from the resource." {
    azure_attribute_absence["azure_monitor_log_profile_retention"]
} else = "Azure Activity log profile retention is currently not set to 365 days or greater" {
    azure_issue["azure_monitor_log_profile_retention"]
}

azure_monitor_log_profile_retention_metadata := {
    "Policy Code": "PR-AZR-TRF-MNT-009",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Activity log profile retention is set to 365 days or greater",
    "Policy Description": "This policy identifies azurerm_monitor_log_profile which have log retention less than 365 days. Activity Logs can be used to check for anomalies and gives insight into suspected breaches or misuse of information and access.",
    "Resource Type": "azurerm_monitor_log_profile",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile"
}

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile

# Manages a Log Profile. A Log Profile configures how Activity Logs are exported.
# It's only possible to configure one Log Profile per Subscription. If you are trying to create more than one Log Profile, an error with StatusCode=409 will occur.
# PR-AZR-TRF-MNT-010
#

default azure_monitor_log_profile_retention_enabled = null

azure_attribute_absence["azure_monitor_log_profile_retention_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_log_profile"
    not resource.properties.retention_policy
}

azure_attribute_absence["azure_monitor_log_profile_retention_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_log_profile"
    retention_policy := resource.properties.retention_policy[_]
    not retention_policy.enabled
}

azure_issue["azure_monitor_log_profile_retention_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_log_profile"
    retention_policy := resource.properties.retention_policy[_]
    retention_policy.enabled != true
}

azure_monitor_log_profile_retention_enabled = false {
    azure_attribute_absence["azure_monitor_log_profile_retention_enabled"]
}

azure_monitor_log_profile_retention_enabled {
    lower(input.resources[_].type) == "azurerm_monitor_log_profile"
    not azure_attribute_absence["azure_monitor_log_profile_retention_enabled"]
    not azure_issue["azure_monitor_log_profile_retention_enabled"]
}

azure_monitor_log_profile_retention_enabled = false {
    azure_issue["azure_monitor_log_profile_retention_enabled"]
}

azure_monitor_log_profile_retention_enabled_err = "azurerm_monitor_log_profile property 'retention_policy.enabled' is missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["azure_monitor_log_profile_retention_enabled"]
} else = "Activity log profile retention is currently not enabled" {
    azure_issue["azure_monitor_log_profile_retention_enabled"]
}

azure_monitor_log_profile_retention_enabled_metadata := {
    "Policy Code": "PR-AZR-TRF-MNT-010",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Activity log profile retention should be enabled",
    "Policy Description": "This policy identifies azurerm_monitor_log_profile which dont have log retention enabled. Activity Logs can be used to check for anomalies and gives insight into suspected breaches or misuse of information and access.",
    "Resource Type": "azurerm_monitor_log_profile",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile

# Manages a Log Profile. A Log Profile configures how Activity Logs are exported.
# It's only possible to configure one Log Profile per Subscription. If you are trying to create more than one Log Profile, an error with StatusCode=409 will occur.
# PR-AZR-TRF-MNT-011
#

default azure_monitor_log_profile_capture_all_activities = null

contains(categories, element) = true {
  lower(categories[_]) == element
} else = false { true }

#no_error {
#    contains([
#            "Action",
#            "Delete",
#            "Write"
#          ], "Action")
#}

azure_attribute_absence["azure_monitor_log_profile_capture_all_activities"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_log_profile"
    not resource.properties.categories
}

no_azure_issue["azure_monitor_log_profile_capture_all_activities"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_log_profile"
    #categories := resource.properties.categories[_]
    #categories := resource.properties.categories
    contains(resource.properties.categories, "action")
    contains(resource.properties.categories, "delete")
    contains(resource.properties.categories, "write")
}

azure_monitor_log_profile_capture_all_activities = false {
    azure_attribute_absence["azure_monitor_log_profile_capture_all_activities"]
}

azure_monitor_log_profile_capture_all_activities {
    lower(input.resources[_].type) == "azurerm_monitor_log_profile"
    not azure_attribute_absence["azure_monitor_log_profile_capture_all_activities"]
    no_azure_issue["azure_monitor_log_profile_capture_all_activities"]
}

azure_monitor_log_profile_capture_all_activities = false {
    lower(input.resources[_].type) == "azurerm_monitor_log_profile"
    not no_azure_issue["azure_monitor_log_profile_capture_all_activities"]
}

azure_monitor_log_profile_capture_all_activities_err = "azurerm_monitor_log_profile property 'categories' is missing from the resource." {
    azure_attribute_absence["azure_monitor_log_profile_capture_all_activities"]
} else = "Activity log audit profile currently not configured to capture all the activities" {
    lower(input.resources[_].type) == "azurerm_monitor_log_profile"
    not no_azure_issue["azure_monitor_log_profile_capture_all_activities"]
}

azure_monitor_log_profile_capture_all_activities_metadata := {
    "Policy Code": "PR-AZR-TRF-MNT-011",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Activity log audit profile should configure to capture all the activities",
    "Policy Description": "This policy identifies azurerm_monitor_log_profile which dont capture all type of activities. Activity Logs can be used to check for anomalies and gives insight into suspected breaches or misuse of information and access.",
    "Resource Type": "azurerm_monitor_log_profile",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile"
}