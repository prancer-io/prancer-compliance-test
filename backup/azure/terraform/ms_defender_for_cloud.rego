package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing
#
# PR-AZR-TRF-MDC-001
#

default mdc_defender_plan_is_on = null

azure_attribute_absence["mdc_defender_plan_is_on"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    not resource.properties.tier
}

azure_issue["mdc_defender_plan_is_on"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.tier) != "standard"
}

mdc_defender_plan_is_on {
    lower(input.resources[_].type) == "azurerm_security_center_subscription_pricing"
    not azure_attribute_absence["mdc_defender_plan_is_on"]
    not azure_issue["mdc_defender_plan_is_on"]
}

mdc_defender_plan_is_on = false {
    azure_attribute_absence["mdc_defender_plan_is_on"]
}

mdc_defender_plan_is_on = false {
    azure_issue["mdc_defender_plan_is_on"]
}

mdc_defender_plan_is_on_err = "Azure Microsoft Defender for Cloud Defender plans is currently not set to On" {
    azure_issue["mdc_defender_plan_is_on"]
} else = "azurerm_security_center_subscription_pricing property 'tier' need to be exist. Its missing from the resource. Please set the value to 'standard' after property addition." {
    azure_attribute_absence["mdc_defender_plan_is_on"]
}

mdc_defender_plan_is_on_metadata := {
    "Policy Code": "PR-AZR-TRF-MDC-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Microsoft Defender for Cloud Defender plans should be set to On",
    "Policy Description": "This policy identifies Azure Microsoft Defender for Cloud which has a Defender setting set to Off. Enabling Azure Defender provides advanced security capabilities like providing threat intelligence, anomaly detection, and behavior analytics in the Azure Microsoft Defender for Cloud. It is highly recommended to enable Azure Defender for all Azure services.",
    "Resource Type": "azurerm_security_center_subscription_pricing",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing
#
# PR-AZR-TRF-MDC-002
#

default mdc_defender_plan_is_on_for_app_services = null

azure_attribute_absence ["mdc_defender_plan_is_on_for_app_services"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    not resource.properties.resource_type
}

azure_attribute_absence ["mdc_defender_plan_is_on_for_app_services"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    not resource.properties.tier    
}

azure_issue ["mdc_defender_plan_is_on_for_app_services"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "appservices"
    lower(resource.properties.tier) != "standard"
}

mdc_defender_plan_is_on_for_app_services {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "appservices"
    not azure_attribute_absence["mdc_defender_plan_is_on_for_app_services"]
    not azure_issue["mdc_defender_plan_is_on_for_app_services"]
}

mdc_defender_plan_is_on_for_app_services = false {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "appservices"
    azure_issue["mdc_defender_plan_is_on_for_app_services"]
}

mdc_defender_plan_is_on_for_app_services = false {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "appservices"
    azure_attribute_absence["mdc_defender_plan_is_on_for_app_services"]

}

mdc_defender_plan_is_on_for_app_services_err = "Azure Microsoft Defender for Cloud is currently not set to On for App Services" {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "appservices"
    azure_issue["mdc_defender_plan_is_on_for_app_services"]
} else = "azurerm_security_center_subscription_pricing property 'tier' and 'resource_type' need to be exist. One or both are missing from the resource." {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "appservices"
    azure_attribute_absence["mdc_defender_plan_is_on_for_app_services"]
}

mdc_defender_plan_is_on_for_app_services_metadata := {
    "Policy Code": "PR-AZR-TRF-MDC-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Microsoft Defender for Cloud should be set to On for App Services",
    "Policy Description": "This policy identifies Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) which has defender setting for App Service is set to Off. Enabling Microsoft Defender for Cloud provides the tools needed to harden your resources, track your security posture, protect against cyberattacks, and streamline security management. It is highly recommended to enable Microsoft Defender for App Service.",
    "Resource Type": "azurerm_security_center_subscription_pricing",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing
#
# PR-AZR-TRF-MDC-003
#

default mdc_defender_plan_is_on_for_azure_sql_databases = null

azure_attribute_absence ["mdc_defender_plan_is_on_for_azure_sql_databases"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    not resource.properties.resource_type
}

azure_attribute_absence ["mdc_defender_plan_is_on_for_azure_sql_databases"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    not resource.properties.tier    
}

azure_issue ["mdc_defender_plan_is_on_for_azure_sql_databases"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "sqlservers"
    lower(resource.properties.tier) != "standard"
}

mdc_defender_plan_is_on_for_azure_sql_databases {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "sqlservers"
    not azure_attribute_absence["mdc_defender_plan_is_on_for_azure_sql_databases"]
    not azure_issue["mdc_defender_plan_is_on_for_azure_sql_databases"]
}

mdc_defender_plan_is_on_for_azure_sql_databases = false {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "sqlservers"
    azure_issue["mdc_defender_plan_is_on_for_azure_sql_databases"]
}

mdc_defender_plan_is_on_for_azure_sql_databases = false {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "sqlservers"
    azure_attribute_absence["mdc_defender_plan_is_on_for_azure_sql_databases"]
}

mdc_defender_plan_is_on_for_azure_sql_databases_err = "Azure Microsoft Defender for Cloud is currently not set to On for Azure SQL Databases" {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "sqlservers"
    azure_issue["mdc_defender_plan_is_on_for_azure_sql_databases"]
} else = "azurerm_security_center_subscription_pricing property 'tier' and 'resource_type' need to be exist. One or both are missing from the resource." {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "sqlservers"
    azure_attribute_absence["mdc_defender_plan_is_on_for_azure_sql_databases"]
}

mdc_defender_plan_is_on_for_azure_sql_databases_metadata := {
    "Policy Code": "PR-AZR-TRF-MDC-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Microsoft Defender for Cloud should be set to On for Azure SQL Databases",
    "Policy Description": "This policy identifies Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) which has defender setting for Azure SQL Databases is set to Off. Enabling Microsoft Defender for Cloud provides the tools needed to harden your resources, track your security posture, protect against cyberattacks, and streamline security management. It is highly recommended to enable Microsoft Defender for Azure SQL Databases.",
    "Resource Type": "azurerm_security_center_subscription_pricing",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing
#
# PR-AZR-TRF-MDC-004
#

default mdc_defender_plan_is_on_for_key_vault = null

azure_attribute_absence ["mdc_defender_plan_is_on_for_key_vault"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    not resource.properties.resource_type
}

azure_attribute_absence ["mdc_defender_plan_is_on_for_key_vault"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    not resource.properties.tier    
}

azure_issue ["mdc_defender_plan_is_on_for_key_vault"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "keyvaults"
    lower(resource.properties.tier) != "standard"
}

mdc_defender_plan_is_on_for_key_vault {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "keyvaults"
    not azure_attribute_absence["mdc_defender_plan_is_on_for_key_vault"]
    not azure_issue["mdc_defender_plan_is_on_for_key_vault"]
}

mdc_defender_plan_is_on_for_key_vault = false {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "keyvaults"
    azure_issue["mdc_defender_plan_is_on_for_key_vault"]
}

mdc_defender_plan_is_on_for_key_vault = false {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "keyvaults"
    azure_attribute_absence["mdc_defender_plan_is_on_for_key_vault"]
}

mdc_defender_plan_is_on_for_key_vault_err = "Azure Microsoft Defender for Cloud is currently not set to On for Key Vault" {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "keyvaults"
    azure_issue["mdc_defender_plan_is_on_for_key_vault"]
} else = "azurerm_security_center_subscription_pricing property 'tier' and 'resource_type' need to be exist. One or both are missing from the resource." {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "keyvaults"
    azure_attribute_absence["mdc_defender_plan_is_on_for_key_vault"]
}

mdc_defender_plan_is_on_for_key_vault_metadata := {
    "Policy Code": "PR-AZR-TRF-MDC-004",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Microsoft Defender for Cloud should be set to On for Key Vault",
    "Policy Description": "This policy identifies Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) which has defender setting for Azure Key Vault is set to Off. Enabling Microsoft Defender for Cloud provides the tools needed to harden your resources, track your security posture, protect against cyberattacks, and streamline security management. It is highly recommended to enable Microsoft Defender for Azure Key Vault.",
    "Resource Type": "azurerm_security_center_subscription_pricing",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing
#
# PR-AZR-TRF-MDC-005
#

default mdc_defender_plan_is_on_for_azure_sql_vm = null

azure_attribute_absence ["mdc_defender_plan_is_on_for_azure_sql_vm"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    not resource.properties.resource_type
}

azure_attribute_absence ["mdc_defender_plan_is_on_for_azure_sql_vm"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    not resource.properties.tier    
}

azure_issue ["mdc_defender_plan_is_on_for_azure_sql_vm"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "sqlservervirtualmachines"
    lower(resource.properties.tier) != "standard"
}

mdc_defender_plan_is_on_for_azure_sql_vm {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "sqlservervirtualmachines"
    not azure_attribute_absence["mdc_defender_plan_is_on_for_azure_sql_vm"]
    not azure_issue["mdc_defender_plan_is_on_for_azure_sql_vm"]
}

mdc_defender_plan_is_on_for_azure_sql_vm = false {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "sqlservervirtualmachines"
    azure_issue["mdc_defender_plan_is_on_for_azure_sql_vm"]
}

mdc_defender_plan_is_on_for_azure_sql_vm = false {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "sqlservervirtualmachines"
    azure_attribute_absence["mdc_defender_plan_is_on_for_azure_sql_vm"]
}

mdc_defender_plan_is_on_for_azure_sql_vm_err = "Azure Microsoft Defender for Cloud is currently not set to On for SQL VM" {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "sqlservervirtualmachines"
    azure_issue["mdc_defender_plan_is_on_for_azure_sql_vm"]
} else = "azurerm_security_center_subscription_pricing property 'tier' and 'resource_type' need to be exist. One or both are missing from the resource." {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "sqlservervirtualmachines"
    azure_attribute_absence["mdc_defender_plan_is_on_for_azure_sql_vm"]
}

mdc_defender_plan_is_on_for_azure_sql_vm_metadata := {
    "Policy Code": "PR-AZR-TRF-MDC-005",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Microsoft Defender for Cloud should be set to On for SQL VM",
    "Policy Description": "This policy identifies Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) which has defender setting for Azure SQL VM is set to Off. Enabling Microsoft Defender for Cloud provides the tools needed to harden your resources, track your security posture, protect against cyberattacks, and streamline security management. It is highly recommended to enable Microsoft Defender for Azure SQL VM.",
    "Resource Type": "azurerm_security_center_subscription_pricing",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing
#
# PR-AZR-TRF-MDC-006
#

default mdc_defender_plan_is_on_for_azure_vm = null

# Defaults to VirtualMachines if empty.
azure_security_center_subscription_pricing_resource_type_attribute_absence ["mdc_defender_plan_is_on_for_azure_vm"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    not resource.properties.resource_type
}

azure_security_center_subscription_pricing_tier_is_standard ["mdc_defender_plan_is_on_for_azure_vm"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.tier) == "standard"
}

azure_attribute_absence ["mdc_defender_plan_is_on_for_azure_vm"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    not resource.properties.tier    
}

azure_issue ["mdc_defender_plan_is_on_for_azure_vm"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "virtualmachines"
    lower(resource.properties.tier) != "standard"
}

mdc_defender_plan_is_on_for_azure_vm {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "virtualmachines"
    not azure_attribute_absence["mdc_defender_plan_is_on_for_azure_vm"]
    not azure_issue["mdc_defender_plan_is_on_for_azure_vm"]
}

mdc_defender_plan_is_on_for_azure_vm = false {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "virtualmachines"
    azure_issue["mdc_defender_plan_is_on_for_azure_vm"]
}

mdc_defender_plan_is_on_for_azure_vm = false {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "virtualmachines"
    azure_attribute_absence["mdc_defender_plan_is_on_for_azure_vm"]
}

mdc_defender_plan_is_on_for_azure_vm {
	lower(input.resources[_].type) == "azurerm_security_center_subscription_pricing"
    azure_security_center_subscription_pricing_resource_type_attribute_absence["mdc_defender_plan_is_on_for_azure_vm"]
    not azure_attribute_absence["mdc_defender_plan_is_on_for_azure_vm"]
    azure_security_center_subscription_pricing_tier_is_standard["mdc_defender_plan_is_on_for_azure_vm"]
}

mdc_defender_plan_is_on_for_azure_vm = false {
	lower(input.resources[_].type) == "azurerm_security_center_subscription_pricing"
    azure_security_center_subscription_pricing_resource_type_attribute_absence["mdc_defender_plan_is_on_for_azure_vm"]
    not azure_attribute_absence["mdc_defender_plan_is_on_for_azure_vm"]
    not azure_security_center_subscription_pricing_tier_is_standard["mdc_defender_plan_is_on_for_azure_vm"]
}

mdc_defender_plan_is_on_for_azure_vm_err = "Azure Microsoft Defender for Cloud is currently not set to On for VMs" {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "virtualmachines"
    azure_issue["mdc_defender_plan_is_on_for_azure_vm"]
} else = "azurerm_security_center_subscription_pricing property 'tier' and 'resource_type' need to be exist. One or both are missing from the resource." {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "virtualmachines"
    azure_attribute_absence["mdc_defender_plan_is_on_for_azure_vm"]
} else = "Azure Microsoft Defender for Cloud is currently not set to On for VMs" {
    lower(input.resources[_].type) == "azurerm_security_center_subscription_pricing"
    azure_security_center_subscription_pricing_resource_type_attribute_absence["mdc_defender_plan_is_on_for_azure_vm"]
    not azure_attribute_absence["mdc_defender_plan_is_on_for_azure_vm"]
    not azure_security_center_subscription_pricing_tier_is_standard["mdc_defender_plan_is_on_for_azure_vm"]
}

mdc_defender_plan_is_on_for_azure_vm_metadata := {
    "Policy Code": "PR-AZR-TRF-MDC-006",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Microsoft Defender for Cloud should be set to On for VMs",
    "Policy Description": "This policy identifies Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) which has defender setting for Azure VM is set to Off. Enabling Microsoft Defender for Cloud provides the tools needed to harden your resources, track your security posture, protect against cyberattacks, and streamline security management. It is highly recommended to enable Microsoft Defender for Azure VM.",
    "Resource Type": "azurerm_security_center_subscription_pricing",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing
#
# PR-AZR-TRF-MDC-007
#

default mdc_defender_plan_is_on_for_azure_storage = null

azure_attribute_absence ["mdc_defender_plan_is_on_for_azure_storage"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    not resource.properties.resource_type
}

azure_attribute_absence ["mdc_defender_plan_is_on_for_azure_storage"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    not resource.properties.tier    
}

azure_issue ["mdc_defender_plan_is_on_for_azure_storage"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "storageaccounts"
    lower(resource.properties.tier) != "standard"
}

mdc_defender_plan_is_on_for_azure_storage {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "storageaccounts"
    not azure_attribute_absence["mdc_defender_plan_is_on_for_azure_storage"]
    not azure_issue["mdc_defender_plan_is_on_for_azure_storage"]
}

mdc_defender_plan_is_on_for_azure_storage = false {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "storageaccounts"
    azure_issue["mdc_defender_plan_is_on_for_azure_storage"]
}

mdc_defender_plan_is_on_for_azure_storage = false {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "storageaccounts"
    azure_attribute_absence["mdc_defender_plan_is_on_for_azure_storage"]
}

mdc_defender_plan_is_on_for_azure_storage_err = "Azure Microsoft Defender for Cloud is currently not set to On for Storage" {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "storageaccounts"
    azure_issue["mdc_defender_plan_is_on_for_azure_storage"]
} else = "azurerm_security_center_subscription_pricing property 'tier' and 'resource_type' need to be exist. One or both are missing from the resource." {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "storageaccounts"
    azure_attribute_absence["mdc_defender_plan_is_on_for_azure_storage"]
}

mdc_defender_plan_is_on_for_azure_storage_metadata := {
    "Policy Code": "PR-AZR-TRF-MDC-007",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Microsoft Defender for Cloud should be set to On for Storage",
    "Policy Description": "This policy identifies Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) which has defender setting for Azure Storage is set to Off. Enabling Microsoft Defender for Cloud provides the tools needed to harden your resources, track your security posture, protect against cyberattacks, and streamline security management. It is highly recommended to enable Microsoft Defender for Azure Storage.",
    "Resource Type": "azurerm_security_center_subscription_pricing",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing
#
# PR-AZR-TRF-MDC-008
#

default mdc_defender_plan_is_on_for_azure_containers = null

azure_attribute_absence ["mdc_defender_plan_is_on_for_azure_containers"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    not resource.properties.resource_type
}

azure_attribute_absence ["mdc_defender_plan_is_on_for_azure_containers"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    not resource.properties.tier    
}

azure_issue ["mdc_defender_plan_is_on_for_azure_containers"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "containers"
    lower(resource.properties.tier) != "standard"
}

mdc_defender_plan_is_on_for_azure_containers {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "containers"
    not azure_attribute_absence["mdc_defender_plan_is_on_for_azure_containers"]
    not azure_issue["mdc_defender_plan_is_on_for_azure_containers"]
}

mdc_defender_plan_is_on_for_azure_containers = false {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "containers"
    azure_issue["mdc_defender_plan_is_on_for_azure_containers"]
}

mdc_defender_plan_is_on_for_azure_containers = false {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "containers"
    azure_attribute_absence["mdc_defender_plan_is_on_for_azure_containers"]
}

mdc_defender_plan_is_on_for_azure_containers_err = "Azure Microsoft Defender for Cloud is currently not set to On for Containers" {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "containers"
    azure_issue["mdc_defender_plan_is_on_for_azure_containers"]
} else = "azurerm_security_center_subscription_pricing property 'tier' and 'resource_type' need to be exist. One or both are missing from the resource." {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.resource_type) == "containers"
    azure_attribute_absence["mdc_defender_plan_is_on_for_azure_containers"]
}

mdc_defender_plan_is_on_for_azure_containers_metadata := {
    "Policy Code": "PR-AZR-TRF-MDC-008",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Microsoft Defender for Cloud should be set to On for Containers",
    "Policy Description": "This policy identifies Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) which has defender setting for Azure Containers is set to Off. Enabling Microsoft Defender for Cloud provides the tools needed to harden your resources, track your security posture, protect against cyberattacks, and streamline security management. It is highly recommended to enable Microsoft Defender for Azure Containers.",
    "Resource Type": "azurerm_security_center_subscription_pricing",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_setting
#
# PR-AZR-TRF-MDC-009
#

default mdc_defender_mcas_integration_enabled = null

azure_attribute_absence ["mdc_defender_mcas_integration_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_setting"
    lower(resource.properties.setting_name) == "mcas"
    not has_property(resource.properties, "enabled") 
}

azure_issue ["mdc_defender_mcas_integration_enabled"] {
    count([c | r := input.resources[_];
              lower(r.type) == "azurerm_security_center_setting";
              lower(r.properties.setting_name) == "mcas";
              r.properties.enabled == true;
              c := 1]) == 0
}

mdc_defender_mcas_integration_enabled {
    lower(input.resources[_].type) == "azurerm_security_center_setting"
    not azure_attribute_absence["mdc_defender_mcas_integration_enabled"]
    not azure_issue["mdc_defender_mcas_integration_enabled"]
}

mdc_defender_mcas_integration_enabled = false {
    azure_issue["mdc_defender_mcas_integration_enabled"]
}

mdc_defender_mcas_integration_enabled = false {
    azure_attribute_absence["mdc_defender_mcas_integration_enabled"]
}

mdc_defender_mcas_integration_enabled_err = "Azure Microsoft Defender for Cloud MCAS integration is currently not enabled" {
    azure_issue["mdc_defender_mcas_integration_enabled"]
} else = "azurerm_security_center_setting property 'setting_name' and 'enabled' need to be exist. One or both are missing from the resource." {
    azure_attribute_absence["mdc_defender_mcas_integration_enabled"]
}

mdc_defender_mcas_integration_enabled_metadata := {
    "Policy Code": "PR-AZR-TRF-MDC-009",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Microsoft Defender for Cloud MCAS integration should be enabled",
    "Policy Description": "This policy identifies Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) which has Microsoft Defender for Cloud Apps (MCAS) integration disabled. Enabling Microsoft Defender for Cloud provides the tools needed to harden your resources, track your security posture, protect against cyberattacks, and streamline security management. It is highly recommended to enable Microsoft Defender for MCAS.",
    "Resource Type": "azurerm_security_center_setting",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_setting"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_setting
#
# PR-AZR-TRF-MDC-010
#

default mdc_defender_wdatp_integration_enabled = null

azure_attribute_absence ["mdc_defender_wdatp_integration_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_setting"
    lower(resource.properties.setting_name) == "wdatp"
    not has_property(resource.properties, "enabled") 
}

azure_issue ["mdc_defender_wdatp_integration_enabled"] {
    count([c | r := input.resources[_];
              lower(r.type) == "azurerm_security_center_setting";
              lower(r.properties.setting_name) == "wdatp";
              r.properties.enabled == true;
              c := 1]) == 0
}

mdc_defender_wdatp_integration_enabled {
    lower(input.resources[_].type) == "azurerm_security_center_setting"
    not azure_attribute_absence["mdc_defender_wdatp_integration_enabled"]
    not azure_issue["mdc_defender_wdatp_integration_enabled"]
}

mdc_defender_wdatp_integration_enabled = false {
    azure_issue["mdc_defender_wdatp_integration_enabled"]
}

mdc_defender_wdatp_integration_enabled = false {
    azure_attribute_absence["mdc_defender_wdatp_integration_enabled"]
}

mdc_defender_wdatp_integration_enabled_err = "Azure Microsoft Defender for Cloud WDATP integration is currently not enabled" {
    azure_issue["mdc_defender_wdatp_integration_enabled"]
} else = "azurerm_security_center_setting property 'setting_name' and 'enabled' need to be exist. One or both are missing from the resource." {
    azure_attribute_absence["mdc_defender_wdatp_integration_enabled"]
}

mdc_defender_wdatp_integration_enabled_metadata := {
    "Policy Code": "PR-AZR-TRF-MDC-010",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Microsoft Defender for Cloud WDATP integration should be enabled",
    "Policy Description": "This policy identifies Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) which has Microsoft Defender for Cloud Apps (WDATP) integration disabled. Enabling Microsoft Defender for Cloud provides the tools needed to harden your resources, track your security posture, protect against cyberattacks, and streamline security management. It is highly recommended to enable Microsoft Defender for WDATP.",
    "Resource Type": "azurerm_security_center_setting",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_setting"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_auto_provisioning
#
# PR-AZR-TRF-MDC-011
#
# There is no resource name required, it will always be "default"

default mdc_defender_provisioning_of_log_analytics_agent_for_vm_is_on = null

azure_attribute_absence ["mdc_defender_provisioning_of_log_analytics_agent_for_vm_is_on"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_auto_provisioning"
    not resource.properties.auto_provision
}

azure_issue ["mdc_defender_provisioning_of_log_analytics_agent_for_vm_is_on"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_auto_provisioning"
    lower(resource.properties.auto_provision) != "on"
}

mdc_defender_provisioning_of_log_analytics_agent_for_vm_is_on {
    lower(input.resources[_].type) == "azurerm_security_center_auto_provisioning"
    not azure_attribute_absence["mdc_defender_provisioning_of_log_analytics_agent_for_vm_is_on"]
    not azure_issue["mdc_defender_provisioning_of_log_analytics_agent_for_vm_is_on"]
}

mdc_defender_provisioning_of_log_analytics_agent_for_vm_is_on = false {
    azure_issue["mdc_defender_provisioning_of_log_analytics_agent_for_vm_is_on"]
}

mdc_defender_provisioning_of_log_analytics_agent_for_vm_is_on = false {
    azure_attribute_absence["mdc_defender_provisioning_of_log_analytics_agent_for_vm_is_on"]
}

mdc_defender_provisioning_of_log_analytics_agent_for_vm_is_on_err = "Azure Microsoft Defender for Cloud provisioning of log analytics agent for vm is currently off" {
    azure_issue["mdc_defender_provisioning_of_log_analytics_agent_for_vm_is_on"]
} else = "azurerm_security_center_setting property 'auto_provision' need to be exist. Its missing from the resource." {
    azure_attribute_absence["mdc_defender_provisioning_of_log_analytics_agent_for_vm_is_on"]
}

mdc_defender_provisioning_of_log_analytics_agent_for_vm_is_on_metadata := {
    "Policy Code": "PR-AZR-TRF-MDC-011",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Microsoft Defender for Cloud automatic provisioning of log Analytics agent for Azure VMs should be turned on",
    "Policy Description": "This policy identifies the Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) which has automatic provisioning of log Analytics agent for Azure VMs is set to Off. Microsoft Defender for Cloud provisions the Microsoft Monitoring Agent on all existing supported Azure virtual machines and any new ones that are created. The Microsoft Monitoring Agent scans for various security-related configurations and events such as system updates, OS vulnerabilities, endpoint protection, and provides alerts.",
    "Resource Type": "azurerm_security_center_auto_provisioning",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_auto_provisioning"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact
#
# PR-AZR-TRF-MDC-012
#

default mdc_defender_security_alert_email_notification_is_on = null

azure_attribute_absence ["mdc_defender_security_alert_email_notification_is_on"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_contact"
    not resource.properties.email
}

azure_attribute_absence ["mdc_defender_security_alert_email_notification_is_on"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_contact"
    not has_property(resource.properties, "alert_notifications")
}

azure_issue ["mdc_defender_security_alert_email_notification_is_on"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_contact"
    count(resource.properties.email) == 0
}

azure_issue ["mdc_defender_security_alert_email_notification_is_on"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_contact"
    resource.properties.alert_notifications != true
}

mdc_defender_security_alert_email_notification_is_on {
    lower(input.resources[_].type) == "azurerm_security_center_contact"
    not azure_attribute_absence["mdc_defender_security_alert_email_notification_is_on"]
    not azure_issue["mdc_defender_security_alert_email_notification_is_on"]
}

mdc_defender_security_alert_email_notification_is_on = false {
    azure_issue["mdc_defender_security_alert_email_notification_is_on"]
}

mdc_defender_security_alert_email_notification_is_on = false {
    azure_attribute_absence["mdc_defender_security_alert_email_notification_is_on"]
}

mdc_defender_security_alert_email_notification_is_on_err = "Azure Microsoft Defender for Cloud security alert email notifications currently not set to On" {
    azure_issue["mdc_defender_security_alert_email_notification_is_on"]
} else = "azurerm_security_center_setting property 'alert_notifications' and 'email' need to be exist. One or both are missing from the resource." {
    azure_attribute_absence["mdc_defender_security_alert_email_notification_is_on"]
}

mdc_defender_security_alert_email_notification_is_on_metadata := {
    "Policy Code": "PR-AZR-TRF-MDC-012",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Microsoft Defender for Cloud security alert email notifications should be set to On",
    "Policy Description": "This policy identifies the Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) which have not set security alert email notifications. Enabling security alert emails ensures that security alert emails are received from Microsoft. This ensures that the right people are aware of any potential security issues and are able to mitigate the risk.",
    "Resource Type": "azurerm_security_center_contact",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact
#
# PR-AZR-TRF-MDC-013
#

default mdc_defender_security_alert_email_notification_for_subscription_owner_is_on = null

azure_attribute_absence ["mdc_defender_security_alert_email_notification_for_subscription_owner_is_on"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_contact"
    not resource.properties.email
}

azure_attribute_absence ["mdc_defender_security_alert_email_notification_for_subscription_owner_is_on"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_contact"
    not has_property(resource.properties, "alerts_to_admins")
}

azure_issue ["mdc_defender_security_alert_email_notification_for_subscription_owner_is_on"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_contact"
    count(resource.properties.email) == 0
}

azure_issue ["mdc_defender_security_alert_email_notification_for_subscription_owner_is_on"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_contact"
    resource.properties.alerts_to_admins != true
}

mdc_defender_security_alert_email_notification_for_subscription_owner_is_on {
    lower(input.resources[_].type) == "azurerm_security_center_contact"
    not azure_attribute_absence["mdc_defender_security_alert_email_notification_for_subscription_owner_is_on"]
    not azure_issue["mdc_defender_security_alert_email_notification_for_subscription_owner_is_on"]
}

mdc_defender_security_alert_email_notification_for_subscription_owner_is_on = false {
    azure_issue["mdc_defender_security_alert_email_notification_for_subscription_owner_is_on"]
}

mdc_defender_security_alert_email_notification_for_subscription_owner_is_on = false {
    azure_attribute_absence["mdc_defender_security_alert_email_notification_for_subscription_owner_is_on"]
}

mdc_defender_security_alert_email_notification_for_subscription_owner_is_on_err = "Azure Microsoft Defender for Cloud security alert email notifications for subscription owner currently not set to On" {
    azure_issue["mdc_defender_security_alert_email_notification_for_subscription_owner_is_on"]
} else = "azurerm_security_center_setting property 'alerts_to_admins' and 'email' need to be exist. One or both are missing from the resource." {
    azure_attribute_absence["mdc_defender_security_alert_email_notification_for_subscription_owner_is_on"]
}

mdc_defender_security_alert_email_notification_for_subscription_owner_is_on_metadata := {
    "Policy Code": "PR-AZR-TRF-MDC-013",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Microsoft Defender for Cloud email notification for subscription owner should be set to On",
    "Policy Description": "This policy identifies the Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) in which email notification for subscription owners is not set. Enabling security alert emails to subscription owners ensures that they receive security alert emails from Microsoft. This ensures that they are aware of any potential security issues and can mitigate the risk in a timely fashion.",
    "Resource Type": "azurerm_security_center_contact",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact"
}



# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact
#
# PR-AZR-TRF-MDC-014
#

default mdc_defender_security_contact_additional_email_is_set = null

azure_attribute_absence ["mdc_defender_security_contact_additional_email_is_set"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_contact"
    not resource.properties.email
}

azure_issue ["mdc_defender_security_contact_additional_email_is_set"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_contact"
    count(resource.properties.email) == 0
}

mdc_defender_security_contact_additional_email_is_set {
    lower(input.resources[_].type) == "azurerm_security_center_contact"
    not azure_attribute_absence["mdc_defender_security_contact_additional_email_is_set"]
    not azure_issue["mdc_defender_security_contact_additional_email_is_set"]
}

mdc_defender_security_contact_additional_email_is_set = false {
    azure_issue["mdc_defender_security_contact_additional_email_is_set"]
}

mdc_defender_security_contact_additional_email_is_set = false {
    azure_attribute_absence["mdc_defender_security_contact_additional_email_is_set"]
}

mdc_defender_security_contact_additional_email_is_set_err = "Azure Microsoft Defender for Cloud security contact additional email is currently not set" {
    azure_issue["mdc_defender_security_contact_additional_email_is_set"]
} else = "azurerm_security_center_setting property 'email' need to be exist. Its missing from the resource." {
    azure_attribute_absence["mdc_defender_security_contact_additional_email_is_set"]
}

mdc_defender_security_contact_additional_email_is_set_metadata := {
    "Policy Code": "PR-AZR-TRF-MDC-014",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Microsoft Defender for Cloud security contact additional email should be set",
    "Policy Description": "This policy identifies the Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) which has not set security contact additional email addresses. Microsoft Defender for Cloud emails the subscription owners whenever a high-severity alert is triggered for their subscription. Providing a security contact email address as an additional email address ensures that the proper people are aware of any potential compromise in order to mitigate the risk in a timely fashion.",
    "Resource Type": "azurerm_security_center_contact",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact"
}

