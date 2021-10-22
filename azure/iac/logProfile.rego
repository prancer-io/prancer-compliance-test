package rule

# https://docs.microsoft.com/en-us/azure/templates/Microsoft.Insights/logprofiles


# PR-AZR-ARM-MNT-009

default log_profiles_retention_days = null

azure_attribute_absence["log_profiles_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    not resource.properties.retentionPolicy.days
    not resource.properties.retentionPolicy.enabled
}

source_path[{"log_profiles_retention_days":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/logprofiles"
    not resource.properties.retentionPolicy.days
    not resource.properties.retentionPolicy.enabled
    metadata:= {
        "resource_path": [["resources",i,"properties","retentionPolicy","days"]]
    }
}

azure_issue_1["log_profiles_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    to_number(resource.properties.retentionPolicy.days) < 365
}

source_path[{"log_profiles_retention_days":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/logprofiles"
    to_number(resource.properties.retentionPolicy.days) < 365
    metadata:= {
        "resource_path": [["resources",i,"properties","retentionPolicy","days"]]
    }
}

azure_issue_1["log_profiles_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    resource.properties.retentionPolicy.enabled != true
}

source_path[{"log_profiles_retention_days":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/logprofiles"
    resource.properties.retentionPolicy.enabled != true
    metadata:= {
        "resource_path": [["resources",i,"properties","retentionPolicy","enabled"]]
    }
}


azure_issue_2["log_profiles_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    to_number(resource.properties.retentionPolicy.days) != 0
}

source_path[{"log_profiles_retention_days":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/logprofiles"
    to_number(resource.properties.retentionPolicy.days) != 0
    metadata:= {
        "resource_path": [["resources",i,"properties","retentionPolicy","days"]]
    }
}

azure_issue_2["log_profiles_retention_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    resource.properties.retentionPolicy.enabled != false
}

source_path[{"log_profiles_retention_days":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/logprofiles"
    resource.properties.retentionPolicy.enabled != false
    metadata:= {
        "resource_path": [["resources",i,"properties","retentionPolicy","enabled"]]
    }
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
    "Policy Code": "PR-AZR-ARM-MNT-009",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "activity log retention should be set to 365 days or greater",
    "Policy Description": "Specifies the retention policy for the log. We recommend you set activity log retention for 365 days or greater. (A value of 0 will retain the events indefinitely.)",
    "Resource Type": "microsoft.insights/logprofiles",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/Microsoft.Insights/logprofiles"
}




# PR-AZR-ARM-MNT-010

default log_profile_category = null
azure_attribute_absence ["log_profile_category"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    not resource.properties.categories
}

source_path[{"log_profiles_retention_days":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.insights/logprofiles"
    not resource.properties.categories
    metadata:= {
        "resource_path": [["resources",i,"properties","categories"]]
    }
}


azure_issue ["log_profile_category"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    contains(lower(resource.properties.categories[_]), "write")
    contains(lower(resource.properties.categories[_]), "delete")
    contains(lower(resource.properties.categories[_]), "action")
}

source_path[{"log_profiles_retention_days":metadata}] {
    resource := input.resources[i]
    contains(lower(resource.properties.categories), "write")
    contains(lower(resource.properties.categories), "delete")
    contains(lower(resource.properties.categories), "action")
    metadata:= {
        "resource_path": [["resources",i,"properties","categories"]]
    }
}

log_profile_category {
    not azure_attribute_absence["log_profile_category"]
    azure_issue["log_profile_category"]
}

log_profile_category = false {
    azure_attribute_absence["log_profile_category"]
}


log_profile_category = false {
    lower(input.resources[_].type) == "microsoft.insights/logprofiles"
    not azure_issue["log_profile_category"]
}



log_profile_category_err = "microsoft.insights/logprofiles property 'categories' missing in the resource." {
    azure_attribute_absence["log_profile_category"]
} else = "Log profile is not configured to capture all activities" {
    lower(input.resources[_].type) == "microsoft.insights/logprofiles"
    not azure_issue["log_profile_category"]
}

log_profile_category_metadata := {
    "Policy Code": "PR-AZR-ARM-MNT-010",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "log profile should be configured to capture all activities",
    "Policy Description": "the categories of the logs. These categories are created as is convenient to the user. Some values are: 'Write', 'Delete', and/or 'Action.' We recommend you configure the log profile to export all activities from the control/management plane.",
    "Resource Type": "microsoft.insights/logprofiles",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/logprofiles"
}