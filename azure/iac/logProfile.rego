package rule

# https://docs.microsoft.com/en-us/azure/templates/Microsoft.Insights/logprofiles


# PR-AZR-0149-ARM

default log_profiles_retention_days = null

azure_attribute_absence["log_profiles_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    not resource.properties.retentionPolicy.days
    not resource.properties.retentionPolicy.enabled
}

azure_issue_1["log_profiles_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    to_number(resource.properties.retentionPolicy.days) < 365
}

azure_issue_1["log_profiles_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    resource.properties.retentionPolicy.enabled != true
}


azure_issue_2["log_profiles_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    to_number(resource.properties.retentionPolicy.days) != 0
}

azure_issue_2["log_profiles_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    resource.properties.retentionPolicy.enabled != false
}


log_profiles_retention_days {
    lower(input.resources[_].type) == "microsoft.insights/logprofiles"
    not azure_attribute_absence["log_profiles_retention_days"]
    not azure_issue_1["log_profiles_retention_days"]
}
log_profiles_retention_days {
    lower(input.resources[_].type) == "microsoft.insights/logprofiles"
    not azure_attribute_absence["log_profiles_retention_days"]
    not azure_issue_2["log_profiles_retention_days"]
}


log_profiles_retention_days = false {
    azure_issue_1["log_profiles_retention_days"]
    azure_issue_2["log_profiles_retention_days"]
}

log_profiles_retention_days = false {
    azure_attribute_absence["log_profiles_retention_days"]
}

log_profiles_retention_days_err = "Microsoft.Insights/logprofiles resource property retentionPolicy.enable missing in the resource" {
    azure_attribute_absence["log_profiles_retention_days"]
} else = "Activity log retention is set to less than 365 days" {
    azure_issue_1["log_profiles_retention_days"]
    azure_issue_2["log_profiles_retention_days"]
}


log_profiles_retention_days_metadata := {
    "Policy Code": "PR-AZR-0149-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "activity log retention should be set to 365 days or greater",
    "Policy Description": "Specifies the retention policy for the log. We recommend you set activity log retention for 365 days or greater. (A value of 0 will retain the events indefinitely.)",
    "Resource Type": "microsoft.insights/logprofiles",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/Microsoft.Insights/logprofiles"
}

