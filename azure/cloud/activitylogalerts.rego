package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/2017-04-01/activitylogalerts

#
# PR-AZR-CLD-MNT-001
#

default alerts = null
# https://docs.microsoft.com/en-us/powershell/module/az.monitor/set-azactivitylogalert?view=azps-6.3.0
# by default alert get enabled if not exist.
azure_attribute_absence["alerts"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.properties.enabled
}

azure_issue["alerts"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    resource.properties.enabled != true
}

alerts {
    azure_attribute_absence["alerts"]
    not azure_issue["alerts"]
}

alerts {
    lower(input.resources[_].type) == "microsoft.insights/activitylogalerts"
    not azure_attribute_absence["alerts"]
    not azure_issue["alerts"]
}

alerts = false {
    azure_issue["alerts"]
}

alerts_err = "Activity log alerts is not enabled" {
    azure_issue["alerts"]
}

alerts_metadata := {
    "Policy Code": "PR-AZR-CLD-MNT-001",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Activity log alerts should be enabled",
    "Policy Description": "Activity log alerts are alerts that activate when a new activity log event occurs that matches the conditions specified in the alert. Based on the order and volume of the events recorded in Azure activity log, the alert rule will fire. Enabling Activity log alerts will allow Azure to send you emails about any high severity alerts in your environment. This will make sure that you are aware of any security issues and take prompt actions to mitigate the risks.",
    "Resource Type": "microsoft.insights/activitylogalerts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/2017-04-01/activitylogalerts"
}



# https://docs.microsoft.com/en-us/azure/templates/Microsoft.Insights/logprofiles


# PR-AZR-CLD-MNT-009

default log_profiles_retention_days = null

azure_attribute_absence["log_profiles_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    not resource.properties.retentionPolicy
}

azure_attribute_absence["log_profiles_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    not resource.properties.retentionPolicy.days
}

azure_issue["log_profiles_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    to_number(resource.properties.retentionPolicy.days) < 365
}

log_profiles_retention_days {
    lower(input.resources[_].type) == "microsoft.insights/logprofiles"
    not azure_attribute_absence["log_profiles_retention_days"]
    not azure_issue["log_profiles_retention_days"]
}



log_profiles_retention_days = false {
    azure_issue["log_profiles_retention_days"]
}

log_profiles_retention_days = false {
    azure_attribute_absence["log_profiles_retention_days"]
}

log_profiles_retention_days_err = "Microsoft.Insights/logprofiles resource property retentionPolicy.days missing in the resource" {
    azure_attribute_absence["log_profiles_retention_days"]
} else = "Activity log retention is set to less than 365 days" {
    azure_issue["log_profiles_retention_days"]
}


log_profiles_retention_days_metadata := {
    "Policy Code": "PR-AZR-CLD-MNT-009",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "activity log retention should be set to 365 days or greater",
    "Policy Description": "Specifies the retention policy for the log. We recommend you set activity log retention for 365 days or greater. (A value of 0 will retain the events indefinitely.)",
    "Resource Type": "microsoft.insights/logprofiles",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/Microsoft.Insights/logprofiles"
}

# PR-AZR-CLD-MNT-010

default log_profiles_retention_enabled = null

azure_attribute_absence["log_profiles_retention_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    not resource.properties.retentionPolicy
}

azure_attribute_absence["log_profiles_retention_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    not resource.properties.retentionPolicy.enabled
}

azure_issue_1["log_profiles_retention_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    resource.properties.retentionPolicy.enabled != true
}

log_profiles_retention_enabled {
    lower(input.resources[_].type) == "microsoft.insights/logprofiles"
    not azure_attribute_absence["log_profiles_retention_enabled"]
    not azure_issue["log_profiles_retention_enabled"]
}

log_profiles_retention_enabled = false {
    azure_issue["log_profiles_retention_enabled"]
}

log_profiles_retention_enabled = false {
    azure_attribute_absence["log_profiles_retention_enabled"]
}

log_profiles_retention_enabled_err = "Microsoft.Insights/logprofiles property 'retentionPolicy.enabled' is missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["log_profiles_retention_enabled"]
} else = "Activity log profile retention is currently not enabled" {
    azure_issue["log_profiles_retention_enabled"]
}


log_profiles_retention_enabled_metadata := {
    "Policy Code": "PR-AZR-CLD-MNT-010",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Activity log profile retention should be enabled",
    "Policy Description": "This policy identifies Microsoft.Insights/logprofiles which don't have log retention enabled. Activity Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access.",
    "Resource Type": "microsoft.insights/logprofiles",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/Microsoft.Insights/logprofiles"
}


# PR-AZR-CLD-MNT-011

default log_profile_category = null
azure_attribute_absence ["log_profile_category"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    not resource.properties.categories
}

no_azure_issue ["log_profile_category"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    contains(lower(resource.properties.categories[_]), "write")
    contains(lower(resource.properties.categories[_]), "delete")
    contains(lower(resource.properties.categories[_]), "action")
}

log_profile_category {
    not azure_attribute_absence["log_profile_category"]
    no_azure_issue["log_profile_category"]
}

log_profile_category = false {
    azure_attribute_absence["log_profile_category"]
}

log_profile_category = false {
    lower(input.resources[_].type) == "microsoft.insights/logprofiles"
    not no_azure_issue["log_profile_category"]
}

log_profile_category_err = "microsoft.insights/logprofiles property 'categories' missing in the resource." {
    azure_attribute_absence["log_profile_category"]
} else = "Log profile is not configured to capture all activities" {
    lower(input.resources[_].type) == "microsoft.insights/logprofiles"
    not no_azure_issue["log_profile_category"]
}

log_profile_category_metadata := {
    "Policy Code": "PR-AZR-CLD-MNT-011",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "log profile should be configured to capture all activities",
    "Policy Description": "the categories of the logs. These categories are created as is convenient to the user. Some values are: 'Write', 'Delete', and/or 'Action.' We recommend you configure the log profile to export all activities from the control/management plane.",
    "Resource Type": "microsoft.insights/logprofiles",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/logprofiles"
}