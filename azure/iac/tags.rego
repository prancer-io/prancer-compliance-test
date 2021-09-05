package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.documentdb/databaseaccounts

# PR-AZR-0105-ARM

default db_account_tagsLength = null

azure_attribute_absence ["db_account_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.documentdb/databaseaccounts"
    not resource.tags
}

azure_issue ["db_account_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.documentdb/databaseaccounts"
    count(resource.tags) == 0
}

db_account_tagsLength {
    lower(input.resources[_].type) == "microsoft.documentdb/databaseaccounts"
    not azure_attribute_absence["db_account_tagsLength"]
    not azure_issue["db_account_tagsLength"]
}

db_account_tagsLength = false {
    azure_issue["db_account_tagsLength"]
}

db_account_tagsLength = false {
    azure_attribute_absence["db_account_tagsLength"]
}


db_account_tagsLength_err = "Resource 'Cosmos DB Account' does not have any associated tag. Please add one." {
    azure_issue["db_account_tagsLength"]
}

db_account_tagsLength_miss_err = "property tags of type Object is absent from resource of type microsoft.documentdb/databaseaccounts" {
    azure_attribute_absence["db_account_tagsLength"]
}


db_account_tagsLength_metadata := {
    "Policy Code": "PR-AZR-0105-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that Cosmos DB Account has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to Azure Cosmos DB resources to better organize them. They are particularly useful when you have many resources of the same type, which in the case of Azure Cosmos DB, is a database. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Two of the key advantages of tagging your Cosmos DB are: Grouping and Filtering and Cost allocation.",
    "Resource Type": "microsoft.documentdb/databaseaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.documentdb/databaseaccounts"
}




# 

# PR-AZR-0160-ARM

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/applicationgateways

default app_gw_tagsLength = null

azure_attribute_absence ["app_gw_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    not resource.tags
}

azure_issue ["app_gw_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    count(resource.tags) == 0
}

app_gw_tagsLength {
    lower(input.resources[_].type) == "microsoft.network/applicationgateways"
    not azure_attribute_absence["app_gw_tagsLength"]
    not azure_issue["app_gw_tagsLength"]
}

app_gw_tagsLength = false {
    azure_issue["app_gw_tagsLength"]
}

app_gw_tagsLength = false {
    azure_attribute_absence["app_gw_tagsLength"]
}


app_gw_tagsLength_err = "property tags of type 'microsoft.network/applicationgateways' Object is absent from resource of type " {
    azure_attribute_absence["app_gw_tagsLength"]
} else = "Resource 'microsoft.network/applicationgateways' does not have any associated tag. Please add one." {
    azure_issue["app_gw_tagsLength"]
}



app_gw_tagsLength_metadata := {
    "Policy Code": "PR-AZR-0160-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that microsoft.network/applicationgateways has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to Application Gateways resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag.",
    "Resource Type": "microsoft.network/applicationgateways",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/applicationgateways"
}


# PR-AZR-0161-ARM

# https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/activitylogalerts

default log_alert_tagsLength = null

azure_attribute_absence ["log_alert_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    not resource.tags
}

azure_issue ["log_alert_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/activitylogalerts"
    count(resource.tags) == 0
}

log_alert_tagsLength {
    lower(input.resources[_].type) == "microsoft.insights/activitylogalerts"
    not azure_attribute_absence["log_alert_tagsLength"]
    not azure_issue["log_alert_tagsLength"]
}

log_alert_tagsLength = false {
    azure_issue["log_alert_tagsLength"]
}

log_alert_tagsLength = false {
    azure_attribute_absence["log_alert_tagsLength"]
}


log_alert_tagsLength_err = "property tags of type 'microsoft.insights/activitylogalerts' Object is absent from resource of type " {
    azure_attribute_absence["log_alert_tagsLength"]
} else = "Resource 'microsoft.insights/activitylogalerts' does not have any associated tag. Please add one." {
    azure_issue["log_alert_tagsLength"]
}



log_alert_tagsLength_metadata := {
    "Policy Code": "PR-AZR-0161-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that microsoft.insights/activitylogalerts has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to Activity Log Alerts resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag.",
    "Resource Type": "microsoft.insights/activitylogalerts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/activitylogalerts"
}


# PR-AZR-0162-ARM

# https://docs.microsoft.com/en-us/azure/templates/microsoft.containerservice/managedclusters

default acr_mc_tagsLength = null

azure_attribute_absence ["acr_mc_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerservice/managedclusters"
    not resource.tags
}

azure_issue ["acr_mc_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerservice/managedclusters"
    count(resource.tags) == 0
}

acr_mc_tagsLength {
    lower(input.resources[_].type) == "microsoft.containerservice/managedclusters"
    not azure_attribute_absence["acr_mc_tagsLength"]
    not azure_issue["acr_mc_tagsLength"]
}

acr_mc_tagsLength = false {
    azure_issue["acr_mc_tagsLength"]
}

acr_mc_tagsLength = false {
    azure_attribute_absence["acr_mc_tagsLength"]
}


acr_mc_tagsLength_err = "property tags of type 'microsoft.containerservice/managedclusters' Object is absent from resource of type " {
    azure_attribute_absence["acr_mc_tagsLength"]
} else = "Resource 'microsoft.containerservice/managedclusters' does not have any associated tag. Please add one." {
    azure_issue["acr_mc_tagsLength"]
}



acr_mc_tagsLength_metadata := {
    "Policy Code": "PR-AZR-0162-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that microsoft.containerservice/managedclusters has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to Managed Clusters resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag.",
    "Resource Type": "microsoft.containerservice/managedclusters",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.containerservice/managedclusters"
}



# PR-AZR-0163-ARM

# https://docs.microsoft.com/en-us/azure/templates/microsoft.databricks/workspaces

default databrick_workspaces_tagsLength = null

azure_attribute_absence ["databrick_workspaces_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.databricks/workspaces"
    not resource.tags
}

azure_issue ["databrick_workspaces_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.databricks/workspaces"
    count(resource.tags) == 0
}

databrick_workspaces_tagsLength {
    lower(input.resources[_].type) == "microsoft.databricks/workspaces"
    not azure_attribute_absence["databrick_workspaces_tagsLength"]
    not azure_issue["databrick_workspaces_tagsLength"]
}

databrick_workspaces_tagsLength = false {
    azure_issue["databrick_workspaces_tagsLength"]
}

databrick_workspaces_tagsLength = false {
    azure_attribute_absence["databrick_workspaces_tagsLength"]
}


databrick_workspaces_tagsLength_err = "property tags of type 'microsoft.databricks/workspaces' Object is absent from resource of type " {
    azure_attribute_absence["databrick_workspaces_tagsLength"]
} else = "Resource 'microsoft.databricks/workspaces' does not have any associated tag. Please add one." {
    azure_issue["databrick_workspaces_tagsLength"]
}



databrick_workspaces_tagsLength_metadata := {
    "Policy Code": "PR-AZR-0163-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that microsoft.databricks/workspaces has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to Databricks Workspaces resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag.",
    "Resource Type": "microsoft.databricks/workspaces",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.databricks/workspaces"
}



# PR-AZR-0164-ARM

# https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformysql/servers

default db_my_sql_tagsLength = null

azure_attribute_absence ["db_my_sql_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformysql/servers"
    not resource.tags
}

azure_issue ["db_my_sql_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformysql/servers"
    count(resource.tags) == 0
}

db_my_sql_tagsLength {
    lower(input.resources[_].type) == "microsoft.dbformysql/servers"
    not azure_attribute_absence["db_my_sql_tagsLength"]
    not azure_issue["db_my_sql_tagsLength"]
}

db_my_sql_tagsLength = false {
    azure_issue["db_my_sql_tagsLength"]
}

db_my_sql_tagsLength = false {
    azure_attribute_absence["db_my_sql_tagsLength"]
}


db_my_sql_tagsLength_err = "property tags of type 'microsoft.dbformysql/servers' Object is absent from resource of type " {
    azure_attribute_absence["db_my_sql_tagsLength"]
} else = "Resource 'microsoft.dbformysql/servers' does not have any associated tag. Please add one." {
    azure_issue["db_my_sql_tagsLength"]
}



db_my_sql_tagsLength_metadata := {
    "Policy Code": "PR-AZR-0164-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that microsoft.dbformysql/servers has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to DB for My SQL servers resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag.",
    "Resource Type": "microsoft.dbformysql/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformysql/servers"
}



# PR-AZR-0165-ARM

# https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/disks

default disks_tagsLength = null

azure_attribute_absence ["disks_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/disks"
    not resource.tags
}

azure_issue ["disks_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/disks"
    count(resource.tags) == 0
}

disks_tagsLength {
    lower(input.resources[_].type) == "microsoft.compute/disks"
    not azure_attribute_absence["disks_tagsLength"]
    not azure_issue["disks_tagsLength"]
}

disks_tagsLength = false {
    azure_issue["disks_tagsLength"]
}

disks_tagsLength = false {
    azure_attribute_absence["disks_tagsLength"]
}


disks_tagsLength_err = "property tags of type 'microsoft.compute/disks' Object is absent from resource of type " {
    azure_attribute_absence["disks_tagsLength"]
} else = "Resource 'microsoft.compute/disks' does not have any associated tag. Please add one." {
    azure_issue["disks_tagsLength"]
}



disks_tagsLength_metadata := {
    "Policy Code": "PR-AZR-0165-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that microsoft.compute/disks has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to Compute Disks resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag.",
    "Resource Type": "microsoft.compute/disks",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/disks"
}




# PR-AZR-0166-ARM

# https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults

default kv_tagsLength = null

azure_attribute_absence ["kv_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    not resource.tags
}

azure_issue ["kv_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    count(resource.tags) == 0
}

kv_tagsLength {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    not azure_attribute_absence["kv_tagsLength"]
    not azure_issue["kv_tagsLength"]
}

kv_tagsLength = false {
    azure_issue["kv_tagsLength"]
}

kv_tagsLength = false {
    azure_attribute_absence["kv_tagsLength"]
}


kv_tagsLength_err = "property tags of type 'microsoft.keyvault/vaults' Object is absent from resource of type " {
    azure_attribute_absence["kv_tagsLength"]
} else = "Resource 'microsoft.keyvault/vaults' does not have any associated tag. Please add one." {
    azure_issue["kv_tagsLength"]
}



kv_tagsLength_metadata := {
    "Policy Code": "PR-AZR-0166-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that microsoft.keyvault/vaults has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to KeyVault resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag.",
    "Resource Type": "microsoft.keyvault/vaults",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults"
}




# PR-AZR-0167-ARM

# https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults/keys

default kv_keys_tagsLength = null

azure_attribute_absence ["kv_keys_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults/keys"
    not resource.tags
}

azure_issue ["kv_keys_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults/keys"
    count(resource.tags) == 0
}

kv_keys_tagsLength {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults/keys"
    not azure_attribute_absence["kv_keys_tagsLength"]
    not azure_issue["kv_keys_tagsLength"]
}

kv_keys_tagsLength = false {
    azure_issue["kv_keys_tagsLength"]
}

kv_keys_tagsLength = false {
    azure_attribute_absence["kv_keys_tagsLength"]
}


kv_keys_tagsLength_err = "property tags of type 'microsoft.keyvault/vaults/keys' Object is absent from resource of type " {
    azure_attribute_absence["kv_keys_tagsLength"]
} else = "Resource 'microsoft.keyvault/vaults/keys' does not have any associated tag. Please add one." {
    azure_issue["kv_keys_tagsLength"]
}



kv_keys_tagsLength_metadata := {
    "Policy Code": "PR-AZR-0167-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that microsoft.keyvault/vaults/keys has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to KeyVault Keys resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag.",
    "Resource Type": "microsoft.keyvault/vaults/keys",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults/keys"
}




# PR-AZR-0168-ARM

# https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults/secrets

default kv_secrets_tagsLength = null

azure_attribute_absence ["kv_secrets_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults/secrets"
    not resource.tags
}

azure_issue ["kv_secrets_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults/secrets"
    count(resource.tags) == 0
}

kv_secrets_tagsLength {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults/secrets"
    not azure_attribute_absence["kv_secrets_tagsLength"]
    not azure_issue["kv_secrets_tagsLength"]
}

kv_secrets_tagsLength = false {
    azure_issue["kv_secrets_tagsLength"]
}

kv_secrets_tagsLength = false {
    azure_attribute_absence["kv_secrets_tagsLength"]
}


kv_secrets_tagsLength_err = "property tags of type 'microsoft.keyvault/vaults/secrets' Object is absent from resource of type " {
    azure_attribute_absence["kv_secrets_tagsLength"]
} else = "Resource 'microsoft.keyvault/vaults/secrets' does not have any associated tag. Please add one." {
    azure_issue["kv_secrets_tagsLength"]
}



kv_secrets_tagsLength_metadata := {
    "Policy Code": "PR-AZR-0168-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that microsoft.keyvault/vaults/secrets has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to KeyVault Secrets resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag.",
    "Resource Type": "microsoft.keyvault/vaults/secrets",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults/secrets"
}





# PR-AZR-0169-ARM

# https://docs.microsoft.com/en-us/azure/templates/Microsoft.Insights/logprofiles

default insights_log_profile_tagsLength = null

azure_attribute_absence ["insights_log_profile_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    not resource.tags
}

azure_issue ["insights_log_profile_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.insights/logprofiles"
    count(resource.tags) == 0
}

insights_log_profile_tagsLength {
    lower(input.resources[_].type) == "microsoft.insights/logprofiles"
    not azure_attribute_absence["insights_log_profile_tagsLength"]
    not azure_issue["insights_log_profile_tagsLength"]
}

insights_log_profile_tagsLength = false {
    azure_issue["insights_log_profile_tagsLength"]
}

insights_log_profile_tagsLength = false {
    azure_attribute_absence["insights_log_profile_tagsLength"]
}


insights_log_profile_tagsLength_err = "property tags of type 'microsoft.insights/logprofiles' Object is absent from resource of type " {
    azure_attribute_absence["insights_log_profile_tagsLength"]
} else = "Resource 'microsoft.insights/logprofiles' does not have any associated tag. Please add one." {
    azure_issue["insights_log_profile_tagsLength"]
}



insights_log_profile_tagsLength_metadata := {
    "Policy Code": "PR-AZR-0169-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that microsoft.insights/logprofiles has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to Insights Log Profiles resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag.",
    "Resource Type": "microsoft.insights/logprofiles",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/Microsoft.Insights/logprofiles"
}




# PR-AZR-0170-ARM

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networkwatchers/flowlogs

default network_watchers_tagsLength = null

azure_attribute_absence ["network_watchers_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    not resource.tags
}

azure_issue ["network_watchers_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networkwatchers/flowlogs"
    count(resource.tags) == 0
}

network_watchers_tagsLength {
    lower(input.resources[_].type) == "microsoft.network/networkwatchers/flowlogs"
    not azure_attribute_absence["network_watchers_tagsLength"]
    not azure_issue["network_watchers_tagsLength"]
}

network_watchers_tagsLength = false {
    azure_issue["network_watchers_tagsLength"]
}

network_watchers_tagsLength = false {
    azure_attribute_absence["network_watchers_tagsLength"]
}


network_watchers_tagsLength_err = "property tags of type 'microsoft.network/networkwatchers/flowlogs' Object is absent from resource of type " {
    azure_attribute_absence["network_watchers_tagsLength"]
} else = "Resource 'microsoft.network/networkwatchers/flowlogs' does not have any associated tag. Please add one." {
    azure_issue["network_watchers_tagsLength"]
}



network_watchers_tagsLength_metadata := {
    "Policy Code": "PR-AZR-0170-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that microsoft.network/networkwatchers/flowlogs has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to Network Watchers Flowlogs resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag.",
    "Resource Type": "microsoft.network/networkwatchers/flowlogs",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networkwatchers/flowlogs"
}





# PR-AZR-0171-ARM

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups

default nsg_tagsLength = null

azure_attribute_absence ["nsg_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    not resource.tags
}

azure_issue ["nsg_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/networksecuritygroups"
    count(resource.tags) == 0
}

nsg_tagsLength {
    lower(input.resources[_].type) == "microsoft.network/networksecuritygroups"
    not azure_attribute_absence["nsg_tagsLength"]
    not azure_issue["nsg_tagsLength"]
}

nsg_tagsLength = false {
    azure_issue["nsg_tagsLength"]
}

nsg_tagsLength = false {
    azure_attribute_absence["nsg_tagsLength"]
}


nsg_tagsLength_err = "property tags of type 'microsoft.network/networksecuritygroups' Object is absent from resource of type " {
    azure_attribute_absence["nsg_tagsLength"]
} else = "Resource 'microsoft.network/networksecuritygroups' does not have any associated tag. Please add one." {
    azure_issue["nsg_tagsLength"]
}



nsg_tagsLength_metadata := {
    "Policy Code": "PR-AZR-0171-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that microsoft.network/networksecuritygroups has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to Network Security Groups resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag.",
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}




# PR-AZR-0172-ARM

# https://docs.microsoft.com/en-us/azure/templates/microsoft.dbforpostgresql/servers

default db_postgresql_tagsLength = null

azure_attribute_absence ["db_postgresql_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    not resource.tags
}

azure_issue ["db_postgresql_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    count(resource.tags) == 0
}

db_postgresql_tagsLength {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    not azure_attribute_absence["db_postgresql_tagsLength"]
    not azure_issue["db_postgresql_tagsLength"]
}

db_postgresql_tagsLength = false {
    azure_issue["db_postgresql_tagsLength"]
}

db_postgresql_tagsLength = false {
    azure_attribute_absence["db_postgresql_tagsLength"]
}


db_postgresql_tagsLength_err = "property tags of type 'microsoft.dbforpostgresql/servers' Object is absent from resource of type " {
    azure_attribute_absence["db_postgresql_tagsLength"]
} else = "Resource 'microsoft.dbforpostgresql/servers' does not have any associated tag. Please add one." {
    azure_issue["db_postgresql_tagsLength"]
}



db_postgresql_tagsLength_metadata := {
    "Policy Code": "PR-AZR-0172-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that microsoft.dbforpostgresql/servers has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to DB for PostgreSQL Servers resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag.",
    "Resource Type": "microsoft.dbforpostgresql/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.dbforpostgresql/servers"
}






# PR-AZR-0173-ARM

# https://docs.microsoft.com/en-us/azure/templates/Microsoft.Cache/redis

default cache_redis_tagsLength = null

azure_attribute_absence ["cache_redis_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    not resource.tags
}

azure_issue ["cache_redis_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cache/redis"
    count(resource.tags) == 0
}

cache_redis_tagsLength {
    lower(input.resources[_].type) == "microsoft.cache/redis"
    not azure_attribute_absence["cache_redis_tagsLength"]
    not azure_issue["cache_redis_tagsLength"]
}

cache_redis_tagsLength = false {
    azure_issue["cache_redis_tagsLength"]
}

cache_redis_tagsLength = false {
    azure_attribute_absence["cache_redis_tagsLength"]
}


cache_redis_tagsLength_err = "property tags of type 'microsoft.cache/redis' Object is absent from resource of type " {
    azure_attribute_absence["cache_redis_tagsLength"]
} else = "Resource 'microsoft.cache/redis' does not have any associated tag. Please add one." {
    azure_issue["cache_redis_tagsLength"]
}



cache_redis_tagsLength_metadata := {
    "Policy Code": "PR-AZR-0173-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that microsoft.cache/redis has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to Cache Redis resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag.",
    "Resource Type": "microsoft.cache/redis",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/Microsoft.Cache/redis"
}





# PR-AZR-0174-ARM

# https://docs.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries

default acr_tagsLength = null

azure_attribute_absence ["acr_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    not resource.tags
}

azure_issue ["acr_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    count(resource.tags) == 0
}

acr_tagsLength {
    lower(input.resources[_].type) == "microsoft.containerregistry/registries"
    not azure_attribute_absence["acr_tagsLength"]
    not azure_issue["acr_tagsLength"]
}

acr_tagsLength = false {
    azure_issue["acr_tagsLength"]
}

acr_tagsLength = false {
    azure_attribute_absence["acr_tagsLength"]
}


acr_tagsLength_err = "property tags of type 'microsoft.containerregistry/registries' Object is absent from resource of type " {
    azure_attribute_absence["acr_tagsLength"]
} else = "Resource 'microsoft.containerregistry/registries' does not have any associated tag. Please add one." {
    azure_issue["acr_tagsLength"]
}



acr_tagsLength_metadata := {
    "Policy Code": "PR-AZR-0174-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that microsoft.containerregistry/registries has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to Container Registry resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag.",
    "Resource Type": "microsoft.containerregistry/registries",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries"
}





# PR-AZR-0175-ARM

# https://docs.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries/webhooks

default acr_webhooks_tagsLength = null

azure_attribute_absence ["acr_webhooks_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries/webhooks"
    not resource.tags
}

azure_issue ["acr_webhooks_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries/webhooks"
    count(resource.tags) == 0
}

acr_webhooks_tagsLength {
    lower(input.resources[_].type) == "microsoft.containerregistry/registries/webhooks"
    not azure_attribute_absence["acr_webhooks_tagsLength"]
    not azure_issue["acr_webhooks_tagsLength"]
}

acr_webhooks_tagsLength = false {
    azure_issue["acr_webhooks_tagsLength"]
}

acr_webhooks_tagsLength = false {
    azure_attribute_absence["acr_webhooks_tagsLength"]
}


acr_webhooks_tagsLength_err = "property tags of type 'microsoft.containerregistry/registries/webhooks' Object is absent from resource of type " {
    azure_attribute_absence["acr_webhooks_tagsLength"]
} else = "Resource 'microsoft.containerregistry/registries/webhooks' does not have any associated tag. Please add one." {
    azure_issue["acr_webhooks_tagsLength"]
}



acr_webhooks_tagsLength_metadata := {
    "Policy Code": "PR-AZR-0175-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that microsoft.containerregistry/registries/webhooks has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to Container Registry Webhooks resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag.",
    "Resource Type": "microsoft.containerregistry/registries/webhooks",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries/webhooks"
}




# PR-AZR-0176-ARM

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances

default sql_managed_instances_tagsLength = null

azure_attribute_absence ["sql_managed_instances_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/managedinstances"
    not resource.tags
}

azure_issue ["sql_managed_instances_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/managedinstances"
    count(resource.tags) == 0
}

sql_managed_instances_tagsLength {
    lower(input.resources[_].type) == "microsoft.sql/managedinstances"
    not azure_attribute_absence["sql_managed_instances_tagsLength"]
    not azure_issue["sql_managed_instances_tagsLength"]
}

sql_managed_instances_tagsLength = false {
    azure_issue["sql_managed_instances_tagsLength"]
}

sql_managed_instances_tagsLength = false {
    azure_attribute_absence["sql_managed_instances_tagsLength"]
}


sql_managed_instances_tagsLength_err = "property tags of type 'microsoft.sql/managedinstances' Object is absent from resource of type " {
    azure_attribute_absence["sql_managed_instances_tagsLength"]
} else = "Resource 'microsoft.sql/managedinstances' does not have any associated tag. Please add one." {
    azure_issue["sql_managed_instances_tagsLength"]
}



sql_managed_instances_tagsLength_metadata := {
    "Policy Code": "PR-AZR-0176-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that microsoft.sql/managedinstances has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to SQL Managed Instances resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag.",
    "Resource Type": "microsoft.sql/managedinstances",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances"
}



# PR-AZR-0177-ARM

# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts

default storage_accounts_tagsLength = null

azure_attribute_absence ["storage_accounts_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    not resource.tags
}

azure_issue ["storage_accounts_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.storage/storageaccounts"
    count(resource.tags) == 0
}

storage_accounts_tagsLength {
    lower(input.resources[_].type) == "microsoft.storage/storageaccounts"
    not azure_attribute_absence["storage_accounts_tagsLength"]
    not azure_issue["storage_accounts_tagsLength"]
}

storage_accounts_tagsLength = false {
    azure_issue["storage_accounts_tagsLength"]
}

storage_accounts_tagsLength = false {
    azure_attribute_absence["storage_accounts_tagsLength"]
}


storage_accounts_tagsLength_err = "property tags of type 'microsoft.storage/storageaccounts' Object is absent from resource of type " {
    azure_attribute_absence["storage_accounts_tagsLength"]
} else = "Resource 'microsoft.storage/storageaccounts' does not have any associated tag. Please add one." {
    azure_issue["storage_accounts_tagsLength"]
}



storage_accounts_tagsLength_metadata := {
    "Policy Code": "PR-AZR-0177-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that microsoft.storage/storageaccounts has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to Storage Accounts resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag.",
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts"
}





# PR-AZR-0178-ARM

# https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines

default vm_tagsLength = null

azure_attribute_absence ["vm_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/virtualmachines"
    not resource.tags
}

azure_issue ["vm_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/virtualmachines"
    count(resource.tags) == 0
}

vm_tagsLength {
    lower(input.resources[_].type) == "microsoft.compute/virtualmachines"
    not azure_attribute_absence["vm_tagsLength"]
    not azure_issue["vm_tagsLength"]
}

vm_tagsLength = false {
    azure_issue["vm_tagsLength"]
}

vm_tagsLength = false {
    azure_attribute_absence["vm_tagsLength"]
}


vm_tagsLength_err = "property tags of type 'microsoft.compute/virtualmachines' Object is absent from resource of type " {
    azure_attribute_absence["vm_tagsLength"]
} else = "Resource 'microsoft.compute/virtualmachines' does not have any associated tag. Please add one." {
    azure_issue["vm_tagsLength"]
}



vm_tagsLength_metadata := {
    "Policy Code": "PR-AZR-0178-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that microsoft.compute/virtualmachines has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to Virtual Machines resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag.",
    "Resource Type": "microsoft.compute/virtualmachines",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines"
}







# PR-AZR-0179-ARM

# https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines/extensions

default vm_extensions_tagsLength = null

azure_attribute_absence ["vm_extensions_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/virtualmachines/extensions"
    not resource.tags
}

azure_issue ["vm_extensions_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/virtualmachines/extensions"
    count(resource.tags) == 0
}

vm_extensions_tagsLength {
    lower(input.resources[_].type) == "microsoft.compute/virtualmachines/extensions"
    not azure_attribute_absence["vm_extensions_tagsLength"]
    not azure_issue["vm_extensions_tagsLength"]
}

vm_extensions_tagsLength = false {
    azure_issue["vm_extensions_tagsLength"]
}

vm_extensions_tagsLength = false {
    azure_attribute_absence["vm_extensions_tagsLength"]
}


vm_extensions_tagsLength_err = "property tags of type 'microsoft.compute/virtualmachines/extensions' Object is absent from resource of type " {
    azure_attribute_absence["vm_extensions_tagsLength"]
} else = "Resource 'microsoft.compute/virtualmachines/extensions' does not have any associated tag. Please add one." {
    azure_issue["vm_extensions_tagsLength"]
}



vm_extensions_tagsLength_metadata := {
    "Policy Code": "PR-AZR-0179-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that microsoft.compute/virtualmachines/extensions has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to Virtual Machines Extensions resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines/extensions"
}






# PR-AZR-0180-ARM

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/virtualnetworks/subnets

default vnet_tagsLength = null

azure_attribute_absence ["vnet_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/virtualnetworks/subnets"
    not resource.tags
}

azure_issue ["vnet_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/virtualnetworks/subnets"
    count(resource.tags) == 0
}

vnet_tagsLength {
    lower(input.resources[_].type) == "microsoft.network/virtualnetworks/subnets"
    not azure_attribute_absence["vnet_tagsLength"]
    not azure_issue["vnet_tagsLength"]
}

vnet_tagsLength = false {
    azure_issue["vnet_tagsLength"]
}

vnet_tagsLength = false {
    azure_attribute_absence["vnet_tagsLength"]
}


vnet_tagsLength_err = "property tags of type 'microsoft.network/virtualnetworks/subnets' Object is absent from resource of type " {
    azure_attribute_absence["vnet_tagsLength"]
} else = "Resource 'microsoft.network/virtualnetworks/subnets' does not have any associated tag. Please add one." {
    azure_issue["vnet_tagsLength"]
}



vnet_tagsLength_metadata := {
    "Policy Code": "PR-AZR-0180-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that microsoft.network/virtualnetworks/subnets has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to Virtual Networks Subnets resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag.",
    "Resource Type": "microsoft.network/virtualnetworks/subnets",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/virtualnetworks/subnets"
}





# PR-AZR-0181-ARM

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/vpngateways

default vnet_vpn_gw_tagsLength = null

azure_attribute_absence ["vnet_vpn_gw_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/vpngateways"
    not resource.tags
}

azure_issue ["vnet_vpn_gw_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/vpngateways"
    count(resource.tags) == 0
}

vnet_vpn_gw_tagsLength {
    lower(input.resources[_].type) == "microsoft.network/vpngateways"
    not azure_attribute_absence["vnet_vpn_gw_tagsLength"]
    not azure_issue["vnet_vpn_gw_tagsLength"]
}

vnet_vpn_gw_tagsLength = false {
    azure_issue["vnet_vpn_gw_tagsLength"]
}

vnet_vpn_gw_tagsLength = false {
    azure_attribute_absence["vnet_vpn_gw_tagsLength"]
}


vnet_vpn_gw_tagsLength_err = "property tags of type 'microsoft.network/vpngateways' Object is absent from resource of type " {
    azure_attribute_absence["vnet_vpn_gw_tagsLength_err"]
} else = "Resource 'microsoft.network/vpngateways' does not have any associated tag. Please add one." {
    azure_issue["vnet_vpn_gw_tagsLength_err"]
}



vnet_vpn_gw_tagsLength_metadata := {
    "Policy Code": "PR-AZR-0181-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that microsoft.network/vpngateways has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to Network VPN Gateways resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag.",
    "Resource Type": "microsoft.network/vpngateways",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/vpngateways"
}






# PR-AZR-0182-ARM

# https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites

default web_sites_tagsLength = null

azure_attribute_absence ["web_sites_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.tags
}

azure_issue ["web_sites_tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    count(resource.tags) == 0
}

web_sites_tagsLength {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["web_sites_tagsLength"]
    not azure_issue["web_sites_tagsLength"]
}

web_sites_tagsLength = false {
    azure_issue["web_sites_tagsLength"]
}

web_sites_tagsLength = false {
    azure_attribute_absence["web_sites_tagsLength"]
}


web_sites_tagsLength_err = "property tags of type 'microsoft.web/sites' Object is absent from resource of type " {
    azure_attribute_absence["web_sites_tagsLength"]
} else = "Resource 'microsoft.web/sites' does not have any associated tag. Please add one." {
    azure_issue["web_sites_tagsLength"]
}



web_sites_tagsLength_metadata := {
    "Policy Code": "PR-AZR-0182-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that microsoft.web/sites has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to Web Sites resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag.",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}
