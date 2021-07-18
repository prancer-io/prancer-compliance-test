package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/logprofiles

# PR-AZR-0119-ARM

default LogProfile = null

azure_issue["LogProfile"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    resource.properties.retentionPolicy.enabled == true
    resource.properties.retentionPolicy.days >= 365
}

LogProfile {
    azure_issue["LogProfile"]
}

LogProfile = false {
    lower(input.resources[_].type) == "microsoft.insights/logprofiles"
    not azure_issue["LogProfile"]
}

LogProfiles_err = "Ensure that Activity Log Retention is set 365 days or greater" {
    lower(input.resources[_].type) == "microsoft.insights/logprofiles"
    not azure_issue["LogProfile"]
}

LogProfile_metadata := {
    "Policy Code": "PR-AZR-0119-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that Activity Log Retention is set 365 days or greater",
    "Policy Description": "Replicate Redis Cache server data to another Redis Cache server using geo replication. This feature is only available for Premium tier Redis Cache. From performance point of view, Microsoft recommends that both Redis Caches (Primary and the linked secondary) reside in the same region.",
    "Resource Type": "microsoft.insights/logprofiles",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/logprofiles"
}



# PR-AZR-0120-ARM

default locations = null

azure_issue["locations"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    count(resource.properties.locations) < 65
    lower(resource.properties.locations) != "global"
}

locations {
    lower(input.resources[_].type) == "microsoft.insights/logprofiles"
    not azure_issue["locations"]
}

locations = false {
    azure_issue["locations"]
}

locations_err = "Ensure the log profile captures activity logs for all regions including global" {
    azure_issue["locations"]
}

locations_metadata := {
    "Policy Code": "PR-AZR-0120-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure the log profile captures activity logs for all regions including global",
    "Policy Description": "Configure the log profile to export activities from all Azure supported regions/locations including global. Rationale: A log profile controls how the activity Log is exported. Ensuring that logs are exported from all the Azure supported regions/locations means that logs for potentially unexpected activities occurring in otherwise unused regions are stored and made available for incident response and investigations. Including global region/location in the log profile locations ensures all events from the control/management plane will be exported, as many events in the activity log are global events.",
    "Resource Type": "microsoft.insights/logprofiles",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/logprofiles"
}