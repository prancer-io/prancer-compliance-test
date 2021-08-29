package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_activity_log_alert

# PR-AZR-0161-TRF

default azurerm_monitor_activity_log_alert_tag_exist = null

azure_attribute_absence ["azurerm_monitor_activity_log_alert_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    not resource.properties.tags
}

azure_issue ["azurerm_monitor_activity_log_alert_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_monitor_activity_log_alert"
    count(resource.tags) == 0
}

azurerm_monitor_activity_log_alert_tag_exist = false {
    azure_attribute_absence["azurerm_monitor_activity_log_alert_tag_exist"]
}

azurerm_monitor_activity_log_alert_tag_exist {
    lower(input.resources[_].type) == "azurerm_monitor_activity_log_alert"
    not azure_attribute_absence["azurerm_monitor_activity_log_alert_tag_exist"]
    not azure_issue["azurerm_monitor_activity_log_alert_tag_exist"]
}

azurerm_monitor_activity_log_alert_tag_exist = false {
    azure_issue["azurerm_monitor_activity_log_alert_tag_exist"]
}

azurerm_monitor_activity_log_alert_tag_exist_err = "azurerm_monitor_activity_log_alert property 'tags' need to be exist. Its missing from the resource." {
    azure_attribute_absence["azurerm_monitor_activity_log_alert_tag_exist"]
} else = "Resource 'azurerm_monitor_activity_log_alert' does not have any associated tag. Please add one." {
    azure_issue["azurerm_monitor_activity_log_alert_tag_exist"]
}

azurerm_monitor_activity_log_alert_tag_exist_metadata := {
    "Policy Code": "PR-AZR-0161-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that Activity Log Alert within Azure Monitor has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Some of the key advantages of tagging is Grouping, Filtering and Cost allocation.",
    "Resource Type": "azurerm_monitor_activity_log_alert",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_activity_log_alert"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster

# PR-AZR-0162-TRF

default azurerm_kubernetes_cluster_tag_exist = null

azure_attribute_absence ["azurerm_kubernetes_cluster_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    not resource.properties.tags
}

azure_issue ["azurerm_kubernetes_cluster_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    count(resource.tags) == 0
}

azurerm_kubernetes_cluster_tag_exist = false {
    azure_attribute_absence["azurerm_kubernetes_cluster_tag_exist"]
}

azurerm_kubernetes_cluster_tag_exist {
    lower(input.resources[_].type) == "azurerm_kubernetes_cluster"
    not azure_attribute_absence["azurerm_kubernetes_cluster_tag_exist"]
    not azure_issue["azurerm_kubernetes_cluster_tag_exist"]
}

azurerm_kubernetes_cluster_tag_exist = false {
    azure_issue["azurerm_kubernetes_cluster_tag_exist"]
}

azurerm_kubernetes_cluster_tag_exist_err = "azurerm_kubernetes_cluster property 'tags' need to be exist. Its missing from the resource." {
    azure_attribute_absence["azurerm_kubernetes_cluster_tag_exist"]
} else = "Resource 'azurerm_kubernetes_cluster' does not have any associated tag. Please add one." {
    azure_issue["azurerm_kubernetes_cluster_tag_exist"]
}

azurerm_kubernetes_cluster_tag_exist_metadata := {
    "Policy Code": "PR-AZR-0162-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that Azure AKS cluster has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Some of the key advantages of tagging is Grouping, Filtering and Cost allocation.",
    "Resource Type": "azurerm_kubernetes_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_gateway

# PR-AZR-0163-TRF

default azurerm_application_gateway_tag_exist = null

azure_attribute_absence ["azurerm_application_gateway_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    not resource.properties.tags
}

azure_issue ["azurerm_application_gateway_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    count(resource.tags) == 0
}

azurerm_application_gateway_tag_exist = false {
    azure_attribute_absence["azurerm_application_gateway_tag_exist"]
}

azurerm_application_gateway_tag_exist {
    lower(input.resources[_].type) == "azurerm_application_gateway"
    not azure_attribute_absence["azurerm_application_gateway_tag_exist"]
    not azure_issue["azurerm_application_gateway_tag_exist"]
}

azurerm_application_gateway_tag_exist = false {
    azure_issue["azurerm_application_gateway_tag_exist"]
}

azurerm_application_gateway_tag_exist_err = "azurerm_application_gateway property 'tags' need to be exist. Its missing from the resource." {
    azure_attribute_absence["azurerm_application_gateway_tag_exist"]
} else = "Resource 'azurerm_application_gateway' does not have any associated tag. Please add one." {
    azure_issue["azurerm_application_gateway_tag_exist"]
}

azurerm_application_gateway_tag_exist_metadata := {
    "Policy Code": "PR-AZR-0163-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that Azure Application Gateway has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Some of the key advantages of tagging is Grouping, Filtering and Cost allocation.",
    "Resource Type": "azurerm_application_gateway",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/application_gateway"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service

# PR-AZR-0164-TRF

default azurerm_app_service_tag_exist = null

azure_attribute_absence ["azurerm_app_service_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    not resource.properties.tags
}

azure_issue ["azurerm_app_service_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    count(resource.tags) == 0
}

azurerm_app_service_tag_exist = false {
    azure_attribute_absence["azurerm_app_service_tag_exist"]
}

azurerm_app_service_tag_exist {
    lower(input.resources[_].type) == "azurerm_app_service"
    not azure_attribute_absence["azurerm_app_service_tag_exist"]
    not azure_issue["azurerm_app_service_tag_exist"]
}

azurerm_app_service_tag_exist = false {
    azure_issue["azurerm_app_service_tag_exist"]
}

azurerm_app_service_tag_exist_err = "azurerm_app_service property 'tags' need to be exist. Its missing from the resource." {
    azure_attribute_absence["azurerm_app_service_tag_exist"]
} else = "Resource 'azurerm_app_service' does not have any associated tag. Please add one." {
    azure_issue["azurerm_app_service_tag_exist"]
}

azurerm_app_service_tag_exist_metadata := {
    "Policy Code": "PR-AZR-0164-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that Azure App Service has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Some of the key advantages of tagging is Grouping, Filtering and Cost allocation.",
    "Resource Type": "azurerm_app_service",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/databricks_workspace

# PR-AZR-0165-TRF

default azurerm_databricks_workspace_tag_exist = null

azure_attribute_absence ["azurerm_databricks_workspace_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_databricks_workspace"
    not resource.properties.tags
}

azure_issue ["azurerm_databricks_workspace_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_databricks_workspace"
    count(resource.tags) == 0
}

azurerm_databricks_workspace_tag_exist = false {
    azure_attribute_absence["azurerm_databricks_workspace_tag_exist"]
}

azurerm_databricks_workspace_tag_exist {
    lower(input.resources[_].type) == "azurerm_databricks_workspace"
    not azure_attribute_absence["azurerm_databricks_workspace_tag_exist"]
    not azure_issue["azurerm_databricks_workspace_tag_exist"]
}

azurerm_databricks_workspace_tag_exist = false {
    azure_issue["azurerm_databricks_workspace_tag_exist"]
}

azurerm_databricks_workspace_tag_exist_err = "azurerm_databricks_workspace property 'tags' need to be exist. Its missing from the resource." {
    azure_attribute_absence["azurerm_databricks_workspace_tag_exist"]
} else = "Resource 'azurerm_databricks_workspace' does not have any associated tag. Please add one." {
    azure_issue["azurerm_databricks_workspace_tag_exist"]
}

azurerm_databricks_workspace_tag_exist_metadata := {
    "Policy Code": "PR-AZR-0165-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that Azure Databricks has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Some of the key advantages of tagging is Grouping, Filtering and Cost allocation.",
    "Resource Type": "azurerm_databricks_workspace",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/databricks_workspace"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_server

# PR-AZR-0166-TRF

default azurerm_sql_server_tag_exist = null

azure_attribute_absence ["azurerm_sql_server_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_server"
    not resource.properties.tags
}

azure_issue ["azurerm_sql_server_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_server"
    count(resource.tags) == 0
}

azurerm_sql_server_tag_exist = false {
    azure_attribute_absence["azurerm_sql_server_tag_exist"]
}

azurerm_sql_server_tag_exist {
    lower(input.resources[_].type) == "azurerm_sql_server"
    not azure_attribute_absence["azurerm_sql_server_tag_exist"]
    not azure_issue["azurerm_sql_server_tag_exist"]
}

azurerm_sql_server_tag_exist = false {
    azure_issue["azurerm_sql_server_tag_exist"]
}

azurerm_sql_server_tag_exist_err = "azurerm_sql_server property 'tags' need to be exist. Its missing from the resource." {
    azure_attribute_absence["azurerm_sql_server_tag_exist"]
} else = "Resource 'azurerm_sql_server' does not have any associated tag. Please add one." {
    azure_issue["azurerm_sql_server_tag_exist"]
}

azurerm_sql_server_tag_exist_metadata := {
    "Policy Code": "PR-AZR-0166-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that SQL Azure Database Server has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Some of the key advantages of tagging is Grouping, Filtering and Cost allocation.",
    "Resource Type": "azurerm_sql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_server"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server

# PR-AZR-0167-TRF

default azurerm_mssql_server_tag_exist = null

azure_attribute_absence ["azurerm_mssql_server_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
    not resource.properties.tags
}

azure_issue ["azurerm_mssql_server_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
    count(resource.tags) == 0
}

azurerm_mssql_server_tag_exist = false {
    azure_attribute_absence["azurerm_mssql_server_tag_exist"]
}

azurerm_mssql_server_tag_exist {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    not azure_attribute_absence["azurerm_mssql_server_tag_exist"]
    not azure_issue["azurerm_mssql_server_tag_exist"]
}

azurerm_mssql_server_tag_exist = false {
    azure_issue["azurerm_mssql_server_tag_exist"]
}

azurerm_mssql_server_tag_exist_err = "azurerm_mssql_server property 'tags' need to be exist. Its missing from the resource." {
    azure_attribute_absence["azurerm_mssql_server_tag_exist"]
} else = "Resource 'azurerm_mssql_server' does not have any associated tag. Please add one." {
    azure_issue["azurerm_mssql_server_tag_exist"]
}

azurerm_mssql_server_tag_exist_metadata := {
    "Policy Code": "PR-AZR-0167-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that MSSQL Azure Database Server has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Some of the key advantages of tagging is Grouping, Filtering and Cost allocation.",
    "Resource Type": "azurerm_mssql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault

# PR-AZR-0168-TRF

default azurerm_key_vault_tag_exist = null

azure_attribute_absence ["azurerm_key_vault_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault"
    not resource.properties.tags
}

azure_issue ["azurerm_key_vault_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault"
    count(resource.tags) == 0
}

azurerm_key_vault_tag_exist = false {
    azure_attribute_absence["azurerm_key_vault_tag_exist"]
}

azurerm_key_vault_tag_exist {
    lower(input.resources[_].type) == "azurerm_key_vault"
    not azure_attribute_absence["azurerm_key_vault_tag_exist"]
    not azure_issue["azurerm_key_vault_tag_exist"]
}

azurerm_key_vault_tag_exist = false {
    azure_issue["azurerm_key_vault_tag_exist"]
}

azurerm_key_vault_tag_exist_err = "azurerm_key_vault property 'tags' need to be exist. Its missing from the resource." {
    azure_attribute_absence["azurerm_key_vault_tag_exist"]
} else = "Resource 'azurerm_key_vault' does not have any associated tag. Please add one." {
    azure_issue["azurerm_key_vault_tag_exist"]
}

azurerm_key_vault_tag_exist_metadata := {
    "Policy Code": "PR-AZR-0168-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that Azure Key Vault has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Some of the key advantages of tagging is Grouping, Filtering and Cost allocation.",
    "Resource Type": "azurerm_key_vault",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/lb

# PR-AZR-0169-TRF

default azurerm_lb_tag_exist = null

azure_attribute_absence ["azurerm_lb_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_lb"
    not resource.properties.tags
}

azure_issue ["azurerm_lb_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_lb"
    count(resource.tags) == 0
}

azurerm_lb_tag_exist = false {
    azure_attribute_absence["azurerm_lb_tag_exist"]
}

azurerm_lb_tag_exist {
    lower(input.resources[_].type) == "azurerm_lb"
    not azure_attribute_absence["azurerm_lb_tag_exist"]
    not azure_issue["azurerm_lb_tag_exist"]
}

azurerm_lb_tag_exist = false {
    azure_issue["azurerm_lb_tag_exist"]
}

azurerm_lb_tag_exist_err = "azurerm_lb property 'tags' need to be exist. Its missing from the resource." {
    azure_attribute_absence["azurerm_lb_tag_exist"]
} else = "Resource 'azurerm_lb' does not have any associated tag. Please add one." {
    azure_issue["azurerm_lb_tag_exist"]
}

azurerm_lb_tag_exist_metadata := {
    "Policy Code": "PR-AZR-0169-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that Azure Load Balancer has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Some of the key advantages of tagging is Grouping, Filtering and Cost allocation.",
    "Resource Type": "azurerm_lb",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/lb"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account

# PR-AZR-0170-TRF

default azurerm_storage_account_tag_exist = null

azure_attribute_absence ["azurerm_storage_account_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    not resource.properties.tags
}

azure_issue ["azurerm_storage_account_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_account"
    count(resource.tags) == 0
}

azurerm_storage_account_tag_exist = false {
    azure_attribute_absence["azurerm_storage_account_tag_exist"]
}

azurerm_storage_account_tag_exist {
    lower(input.resources[_].type) == "azurerm_storage_account"
    not azure_attribute_absence["azurerm_storage_account_tag_exist"]
    not azure_issue["azurerm_storage_account_tag_exist"]
}

azurerm_storage_account_tag_exist = false {
    azure_issue["azurerm_storage_account_tag_exist"]
}

azurerm_storage_account_tag_exist_err = "azurerm_storage_account property 'tags' need to be exist. Its missing from the resource." {
    azure_attribute_absence["azurerm_storage_account_tag_exist"]
} else = "Resource 'azurerm_storage_account' does not have any associated tag. Please add one." {
    azure_issue["azurerm_storage_account_tag_exist"]
}

azurerm_storage_account_tag_exist_metadata := {
    "Policy Code": "PR-AZR-0170-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that Azure Storage Account has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Some of the key advantages of tagging is Grouping, Filtering and Cost allocation.",
    "Resource Type": "azurerm_storage_account",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_key

# PR-AZR-0171-TRF

default azurerm_key_vault_key_tag_exist = null

azure_attribute_absence ["azurerm_key_vault_key_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault_key"
    not resource.properties.tags
}

azure_issue ["azurerm_key_vault_key_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault_key"
    count(resource.tags) == 0
}

azurerm_key_vault_key_tag_exist = false {
    azure_attribute_absence["azurerm_key_vault_key_tag_exist"]
}

azurerm_key_vault_key_tag_exist {
    lower(input.resources[_].type) == "azurerm_key_vault_key"
    not azure_attribute_absence["azurerm_key_vault_key_tag_exist"]
    not azure_issue["azurerm_key_vault_key_tag_exist"]
}

azurerm_key_vault_key_tag_exist = false {
    azure_issue["azurerm_key_vault_key_tag_exist"]
}

azurerm_key_vault_key_tag_exist_err = "azurerm_key_vault_key property 'tags' need to be exist. Its missing from the resource." {
    azure_attribute_absence["azurerm_key_vault_key_tag_exist"]
} else = "Resource 'azurerm_key_vault_key' does not have any associated tag. Please add one." {
    azure_issue["azurerm_key_vault_key_tag_exist"]
}

azurerm_key_vault_key_tag_metadata := {
    "Policy Code": "PR-AZR-0171-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that Azure Key Vault keys has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Some of the key advantages of tagging is Grouping, Filtering and Cost allocation.",
    "Resource Type": "azurerm_key_vault_key",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_key"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/managed_disk

# PR-AZR-0172-TRF

default azurerm_managed_disk_tag_exist = null

azure_attribute_absence ["azurerm_managed_disk_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_managed_disk"
    not resource.properties.tags
}

azure_issue ["azurerm_managed_disk_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_managed_disk"
    count(resource.tags) == 0
}

azurerm_managed_disk_tag_exist = false {
    azure_attribute_absence["azurerm_managed_disk_tag_exist"]
}

azurerm_managed_disk_tag_exist {
    lower(input.resources[_].type) == "azurerm_managed_disk"
    not azure_attribute_absence["azurerm_managed_disk_tag_exist"]
    not azure_issue["azurerm_managed_disk_tag_exist"]
}

azurerm_managed_disk_tag_exist = false {
    azure_issue["azurerm_managed_disk_tag_exist"]
}

azurerm_managed_disk_tag_exist_err = "azurerm_managed_disk property 'tags' need to be exist. Its missing from the resource." {
    azure_attribute_absence["azurerm_managed_disk_tag_exist"]
} else = "Resource 'azurerm_managed_disk' does not have any associated tag. Please add one." {
    azure_issue["azurerm_managed_disk_tag_exist"]
}

azurerm_managed_disk_tag_exist_metadata := {
    "Policy Code": "PR-AZR-0172-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that Azure Managed Disk has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Some of the key advantages of tagging is Grouping, Filtering and Cost allocation.",
    "Resource Type": "azurerm_managed_disk",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/managed_disk"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret

# PR-AZR-0173-TRF

default azurerm_key_vault_secret_tag_exist = null

azure_attribute_absence ["azurerm_key_vault_secret_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault_secret"
    not resource.properties.tags
}

azure_issue ["azurerm_key_vault_secret_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault_secret"
    count(resource.tags) == 0
}

azurerm_key_vault_secret_tag_exist = false {
    azure_attribute_absence["azurerm_key_vault_secret_tag_exist"]
}

azurerm_key_vault_secret_tag_exist {
    lower(input.resources[_].type) == "azurerm_key_vault_secret"
    not azure_attribute_absence["azurerm_key_vault_secret_tag_exist"]
    not azure_issue["azurerm_key_vault_secret_tag_exist"]
}

azurerm_key_vault_secret_tag_exist = false {
    azure_issue["azurerm_key_vault_secret_tag_exist"]
}

azurerm_key_vault_secret_tag_exist_err = "azurerm_key_vault_secret property 'tags' need to be exist. Its missing from the resource." {
    azure_attribute_absence["azurerm_key_vault_secret_tag_exist"]
} else = "Resource 'azurerm_key_vault_secret' does not have any associated tag. Please add one." {
    azure_issue["azurerm_key_vault_secret_tag_exist"]
}

azurerm_key_vault_secret_tag_exist_metadata := {
    "Policy Code": "PR-AZR-0173-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that Azure Key Vault secrets has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Some of the key advantages of tagging is Grouping, Filtering and Cost allocation.",
    "Resource Type": "azurerm_key_vault_secret",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_server

# PR-AZR-0174-TRF

default azurerm_mariadb_server_tag_exist = null

azure_attribute_absence ["azurerm_mariadb_server_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mariadb_server"
    not resource.properties.tags
}

azure_issue ["azurerm_mariadb_server_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mariadb_server"
    count(resource.tags) == 0
}

azurerm_mariadb_server_tag_exist = false {
    azure_attribute_absence["azurerm_mariadb_server_tag_exist"]
}

azurerm_mariadb_server_tag_exist {
    lower(input.resources[_].type) == "azurerm_mariadb_server"
    not azure_attribute_absence["azurerm_mariadb_server_tag_exist"]
    not azure_issue["azurerm_mariadb_server_tag_exist"]
}

azurerm_mariadb_server_tag_exist = false {
    azure_issue["azurerm_mariadb_server_tag_exist"]
}

azurerm_mariadb_server_tag_exist_err = "azurerm_mariadb_server property 'tags' need to be exist. Its missing from the resource." {
    azure_attribute_absence["azurerm_mariadb_server_tag_exist"]
} else = "Resource 'azurerm_mariadb_server' does not have any associated tag. Please add one." {
    azure_issue["azurerm_mariadb_server_tag_exist"]
}

azurerm_mariadb_server_tag_exist_metadata := {
    "Policy Code": "PR-AZR-0174-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that MariaDB Server has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Some of the key advantages of tagging is Grouping, Filtering and Cost allocation.",
    "Resource Type": "azurerm_mariadb_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_server"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server

# PR-AZR-0175-TRF

default azurerm_mysql_server_tag_exist = null

azure_attribute_absence ["azurerm_mysql_server_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mysql_server"
    not resource.properties.tags
}

azure_issue ["azurerm_mysql_server_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mysql_server"
    count(resource.tags) == 0
}

azurerm_mysql_server_tag_exist = false {
    azure_attribute_absence["azurerm_mysql_server_tag_exist"]
}

azurerm_mysql_server_tag_exist {
    lower(input.resources[_].type) == "azurerm_mysql_server"
    not azure_attribute_absence["azurerm_mysql_server_tag_exist"]
    not azure_issue["azurerm_mysql_server_tag_exist"]
}

azurerm_mysql_server_tag_exist = false {
    azure_issue["azurerm_mysql_server_tag_exist"]
}

azurerm_mysql_server_tag_exist_err = "azurerm_mysql_server property 'tags' need to be exist. Its missing from the resource." {
    azure_attribute_absence["azurerm_mysql_server_tag_exist"]
} else = "Resource 'azurerm_mysql_server' does not have any associated tag. Please add one." {
    azure_issue["azurerm_mysql_server_tag_exist"]
}

azurerm_mysql_server_tag_exist_metadata := {
    "Policy Code": "PR-AZR-0175-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that MySQL Server has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Some of the key advantages of tagging is Grouping, Filtering and Cost allocation.",
    "Resource Type": "azurerm_mysql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_watcher_flow_log

# PR-AZR-0176-TRF

default azurerm_network_watcher_flow_log_tag_exist = null

azure_attribute_absence ["azurerm_network_watcher_flow_log_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_network_watcher_flow_log"
    not resource.properties.tags
}

azure_issue ["azurerm_network_watcher_flow_log_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_network_watcher_flow_log"
    count(resource.tags) == 0
}

azurerm_network_watcher_flow_log_tag_exist = false {
    azure_attribute_absence["azurerm_network_watcher_flow_log_tag_exist"]
}

azurerm_network_watcher_flow_log_tag_exist {
    lower(input.resources[_].type) == "azurerm_network_watcher_flow_log"
    not azure_attribute_absence["azurerm_network_watcher_flow_log_tag_exist"]
    not azure_issue["azurerm_network_watcher_flow_log_tag_exist"]
}

azurerm_network_watcher_flow_log_tag_exist = false {
    azure_issue["azurerm_network_watcher_flow_log_tag_exist"]
}

azurerm_network_watcher_flow_log_tag_exist_err = "azurerm_network_watcher_flow_log property 'tags' need to be exist. Its missing from the resource." {
    azure_attribute_absence["azurerm_network_watcher_flow_log_tag_exist"]
} else = "Resource 'azurerm_network_watcher_flow_log' does not have any associated tag. Please add one." {
    azure_issue["azurerm_network_watcher_flow_log_tag_exist"]
}

azurerm_network_watcher_flow_log_tag_exist_metadata := {
    "Policy Code": "PR-AZR-0176-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that Network Watcher Flow Log has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Some of the key advantages of tagging is Grouping, Filtering and Cost allocation.",
    "Resource Type": "azurerm_network_watcher_flow_log",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_watcher_flow_log"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_group

# PR-AZR-0177-TRF

default azurerm_network_security_group_tag_exist = null

azure_attribute_absence ["azurerm_network_security_group_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_network_security_group"
    not resource.properties.tags
}

azure_issue ["azurerm_network_security_group_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_network_security_group"
    count(resource.tags) == 0
}

azurerm_network_security_group_tag_exist = false {
    azure_attribute_absence["azurerm_network_security_group_tag_exist"]
}

azurerm_network_security_group_tag_exist {
    lower(input.resources[_].type) == "azurerm_network_security_group"
    not azure_attribute_absence["azurerm_network_security_group_tag_exist"]
    not azure_issue["azurerm_network_security_group_tag_exist"]
}

azurerm_network_security_group_tag_exist = false {
    azure_issue["azurerm_network_security_group_tag_exist"]
}

azurerm_network_security_group_tag_exist_err = "azurerm_network_security_group property 'tags' need to be exist. Its missing from the resource." {
    azure_attribute_absence["azurerm_network_security_group_tag_exist"]
} else = "Resource 'azurerm_network_security_group' does not have any associated tag. Please add one." {
    azure_issue["azurerm_network_security_group_tag_exist"]
}

azurerm_network_security_group_tag_exist_metadata := {
    "Policy Code": "PR-AZR-0177-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that Network Security Group has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Some of the key advantages of tagging is Grouping, Filtering and Cost allocation.",
    "Resource Type": "azurerm_network_security_group",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_group"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_server

# PR-AZR-0178-TRF

default azurerm_postgresql_server_tag_exist = null

azure_attribute_absence ["azurerm_postgresql_server_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_postgresql_server"
    not resource.properties.tags
}

azure_issue ["azurerm_postgresql_server_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_postgresql_server"
    count(resource.tags) == 0
}

azurerm_postgresql_server_tag_exist = false {
    azure_attribute_absence["azurerm_postgresql_server_tag_exist"]
}

azurerm_postgresql_server_tag_exist {
    lower(input.resources[_].type) == "azurerm_postgresql_server"
    not azure_attribute_absence["azurerm_postgresql_server_tag_exist"]
    not azure_issue["azurerm_postgresql_server_tag_exist"]
}

azurerm_postgresql_server_tag_exist = false {
    azure_issue["azurerm_postgresql_server_tag_exist"]
}

azurerm_postgresql_server_tag_exist_err = "azurerm_postgresql_server property 'tags' need to be exist. Its missing from the resource." {
    azure_attribute_absence["azurerm_postgresql_server_tag_exist"]
} else = "Resource 'azurerm_postgresql_server' does not have any associated tag. Please add one." {
    azure_issue["azurerm_postgresql_server_tag_exist"]
}

azurerm_postgresql_server_tag_exist_metadata := {
    "Policy Code": "PR-AZR-0178-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that PostgreSQL Database Server has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Some of the key advantages of tagging is Grouping, Filtering and Cost allocation.",
    "Resource Type": "azurerm_postgresql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_server"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_cache

# PR-AZR-0179-TRF

default azurerm_redis_cache_tag_exist = null

azure_attribute_absence ["azurerm_redis_cache_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_redis_cache"
    not resource.properties.tags
}

azure_issue ["azurerm_redis_cache_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_redis_cache"
    count(resource.tags) == 0
}

azurerm_redis_cache_tag_exist = false {
    azure_attribute_absence["azurerm_redis_cache_tag_exist"]
}

azurerm_redis_cache_tag_exist {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    not azure_attribute_absence["azurerm_redis_cache_tag_exist"]
    not azure_issue["azurerm_redis_cache_tag_exist"]
}

azurerm_redis_cache_tag_exist = false {
    azure_issue["azurerm_redis_cache_tag_exist"]
}

azurerm_redis_cache_tag_exist_err = "azurerm_redis_cache property 'tags' need to be exist. Its missing from the resource." {
    azure_attribute_absence["azurerm_redis_cache_tag_exist"]
} else = "Resource 'azurerm_redis_cache' does not have any associated tag. Please add one." {
    azure_issue["azurerm_redis_cache_tag_exist"]
}

azurerm_redis_cache_tag_exist_metadata := {
    "Policy Code": "PR-AZR-0179-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that Redis Cache has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Some of the key advantages of tagging is Grouping, Filtering and Cost allocation.",
    "Resource Type": "azurerm_redis_cache",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_cache"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_registry

# PR-AZR-0180-TRF

default azurerm_container_registry_tag_exist = null

azure_attribute_absence ["azurerm_container_registry_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    not resource.properties.tags
}

azure_issue ["azurerm_container_registry_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    count(resource.tags) == 0
}

azurerm_container_registry_tag_exist = false {
    azure_attribute_absence["azurerm_container_registry_tag_exist"]
}

azurerm_container_registry_tag_exist {
    lower(input.resources[_].type) == "azurerm_container_registry"
    not azure_attribute_absence["azurerm_container_registry_tag_exist"]
    not azure_issue["azurerm_container_registry_tag_exist"]
}

azurerm_container_registry_tag_exist = false {
    azure_issue["azurerm_container_registry_tag_exist"]
}

azurerm_container_registry_tag_exist_err = "azurerm_container_registry property 'tags' need to be exist. Its missing from the resource." {
    azure_attribute_absence["azurerm_container_registry_tag_exist"]
} else = "Resource 'azurerm_container_registry' does not have any associated tag. Please add one." {
    azure_issue["azurerm_container_registry_tag_exist"]
}

azurerm_container_registry_tag_exist_metadata := {
    "Policy Code": "PR-AZR-0180-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that Azure Container Registry has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Some of the key advantages of tagging is Grouping, Filtering and Cost allocation.",
    "Resource Type": "azurerm_container_registry",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_registry"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine

# PR-AZR-0181-TRF

default azurerm_virtual_machine_tag_exist = null

azure_attribute_absence ["azurerm_virtual_machine_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_machine"
    not resource.properties.tags
}

azure_issue ["azurerm_virtual_machine_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_machine"
    count(resource.tags) == 0
}

azurerm_virtual_machine_tag_exist = false {
    azure_attribute_absence["azurerm_virtual_machine_tag_exist"]
}

azurerm_virtual_machine_tag_exist {
    lower(input.resources[_].type) == "azurerm_virtual_machine"
    not azure_attribute_absence["azurerm_virtual_machine_tag_exist"]
    not azure_issue["azurerm_virtual_machine_tag_exist"]
}

azurerm_virtual_machine_tag_exist = false {
    azure_issue["azurerm_virtual_machine_tag_exist"]
}

azurerm_virtual_machine_tag_exist_err = "azurerm_virtual_machine property 'tags' need to be exist. Its missing from the resource." {
    azure_attribute_absence["azurerm_virtual_machine_tag_exist"]
} else = "Resource 'azurerm_virtual_machine' does not have any associated tag. Please add one." {
    azure_issue["azurerm_virtual_machine_tag_exist"]
}

azurerm_virtual_machine_tag_exist_metadata := {
    "Policy Code": "PR-AZR-0181-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that Azure Virtual Machine has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Some of the key advantages of tagging is Grouping, Filtering and Cost allocation.",
    "Resource Type": "azurerm_virtual_machine",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine_extension

# PR-AZR-0182-TRF

default azurerm_virtual_machine_extension_tag_exist = null

azure_attribute_absence ["azurerm_virtual_machine_extension_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_machine_extension"
    not resource.properties.tags
}

azure_issue ["azurerm_virtual_machine_extension_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_machine_extension"
    count(resource.tags) == 0
}

azurerm_virtual_machine_extension_tag_exist = false {
    azure_attribute_absence["azurerm_virtual_machine_extension_tag_exist"]
}

azurerm_virtual_machine_extension_tag_exist {
    lower(input.resources[_].type) == "azurerm_virtual_machine_extension"
    not azure_attribute_absence["azurerm_virtual_machine_extension_tag_exist"]
    not azure_issue["azurerm_virtual_machine_extension_tag_exist"]
}

azurerm_virtual_machine_extension_tag_exist = false {
    azure_issue["azurerm_virtual_machine_extension_tag_exist"]
}

azurerm_virtual_machine_extension_tag_exist_err = "azurerm_virtual_machine_extension property 'tags' need to be exist. Its missing from the resource." {
    azure_attribute_absence["azurerm_virtual_machine_extension_tag_exist"]
} else = "Resource 'azurerm_virtual_machine_extension' does not have any associated tag. Please add one." {
    azure_issue["azurerm_virtual_machine_extension_tag_exist"]
}

azurerm_virtual_machine_extension_tag_exist_metadata := {
    "Policy Code": "PR-AZR-0182-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that Azure Virtual Machine Extension has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Some of the key advantages of tagging is Grouping, Filtering and Cost allocation.",
    "Resource Type": "azurerm_virtual_machine_extension",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine_extension"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_network_gateway_connection

# PR-AZR-0183-TRF

default azurerm_virtual_network_gateway_connection_tag_exist = null

azure_attribute_absence ["azurerm_virtual_network_gateway_connection_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_network_gateway_connection"
    not resource.properties.tags
}

azure_issue ["azurerm_virtual_network_gateway_connection_tag_exist"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_network_gateway_connection"
    count(resource.tags) == 0
}

azurerm_virtual_network_gateway_connection_tag_exist = false {
    azure_attribute_absence["azurerm_virtual_network_gateway_connection_tag_exist"]
}

azurerm_virtual_network_gateway_connection_tag_exist {
    lower(input.resources[_].type) == "azurerm_virtual_network_gateway_connection"
    not azure_attribute_absence["azurerm_virtual_network_gateway_connection_tag_exist"]
    not azure_issue["azurerm_virtual_network_gateway_connection_tag_exist"]
}

azurerm_virtual_network_gateway_connection_tag_exist = false {
    azure_issue["azurerm_virtual_network_gateway_connection_tag_exist"]
}

azurerm_virtual_network_gateway_connection_tag_exist_err = "azurerm_virtual_network_gateway_connection property 'tags' need to be exist. Its missing from the resource." {
    azure_attribute_absence["azurerm_virtual_network_gateway_connection_tag_exist"]
} else = "Resource 'azurerm_virtual_network_gateway_connection' does not have any associated tag. Please add one." {
    azure_issue["azurerm_virtual_network_gateway_connection_tag_exist"]
}

azurerm_virtual_network_gateway_connection_tag_exist_metadata := {
    "Policy Code": "PR-AZR-0183-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that Virtual Network Gateway has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Some of the key advantages of tagging is Grouping, Filtering and Cost allocation.",
    "Resource Type": "azurerm_virtual_network_gateway_connection",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_network_gateway_connection"
}