package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances

#
# Always use Private Endpoint for Azure SQL Database and SQL Managed Instance
#

#
# PR-AZR-0116-ARM
#

default sql_mi_public_endpoint_disabled = null

# https://docs.microsoft.com/en-us/powershell/module/az.sql/set-azsqlinstance?view=azps-6.2.1
# if property does not exist default is false
azure_attribute_absence["sql_mi_public_endpoint_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/managedinstances"
    not resource.properties.publicDataEndpointEnabled
}

source_path[{"sql_mi_public_endpoint_disabled":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/managedinstances"
    not resource.properties.publicDataEndpointEnabled
    metadata:= {
        "resource_path": [["resources",i,"properties","publicDataEndpointEnabled"]]
    }
}

azure_issue["sql_mi_public_endpoint_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/managedinstances"
    resource.properties.publicDataEndpointEnabled != "false"
}

source_path[{"sql_mi_public_endpoint_disabled":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/managedinstances"
    resource.properties.publicDataEndpointEnabled != "false"
    metadata:= {
        "resource_path": [["resources",i,"properties","publicDataEndpointEnabled"]]
    }
}

sql_mi_public_endpoint_disabled {
    lower(input.resources[_].type) == "microsoft.sql/managedinstances"
    not azure_attribute_absence["sql_mi_public_endpoint_disabled"]
    not azure_issue["sql_mi_public_endpoint_disabled"]
}

sql_mi_public_endpoint_disabled {
    azure_attribute_absence["sql_mi_public_endpoint_disabled"]
}

sql_mi_public_endpoint_disabled = false {
    azure_issue["sql_mi_public_endpoint_disabled"]
}

sql_mi_public_endpoint_disabled_err = "SQL Managed Instance currently have public endpoint enabled. Please disable" {
    azure_issue["sql_mi_public_endpoint_disabled"]
}

sql_mi_public_endpoint_disabled_metadata := {
    "Policy Code": "PR-AZR-0116-ARM",
    "Type": "IaC",
    "Product": "",
    "Language": "ARM template",
    "Policy Title": "SQL Managed Instance should have public endpoint access disabled",
    "Policy Description": "Always use Private Endpoint for Azure SQL Database and SQL Managed Instance",
    "Resource Type": "microsoft.sql/managedinstances",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances"
}
