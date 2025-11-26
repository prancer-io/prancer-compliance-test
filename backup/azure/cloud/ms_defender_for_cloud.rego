package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }

# https://learn.microsoft.com/en-us/azure/templates/microsoft.security/pricings?pivots=deployment-language-arm-template
# https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/list?tabs=HTTP
#
# PR-AZR-CLD-MDC-001
#

default mdc_defender_plan_is_on = null

azure_attribute_absence["mdc_defender_plan_is_on"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    not resource.properties.pricingTier
}

azure_issue["mdc_defender_plan_is_on"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.properties.pricingTier) != "standard"
    not resource.properties.deprecated
}

mdc_defender_plan_is_on {
    lower(input.resources[_].type) == "microsoft.security/pricings"
    not azure_issue["mdc_defender_plan_is_on"]
    not azure_attribute_absence["mdc_defender_plan_is_on"]
}

mdc_defender_plan_is_on = false {
    azure_issue["mdc_defender_plan_is_on"]
}

mdc_defender_plan_is_on = false {
    azure_attribute_absence["mdc_defender_plan_is_on"]
}

mdc_defender_plan_is_on_err = "Azure Microsoft Defender for Cloud Defender plans is currently not set to On" {
    azure_issue["mdc_defender_plan_is_on"]
} else = "microsoft.security/pricings attribute pricingTier is missing from the resource" {
    azure_attribute_absence["mdc_defender_plan_is_on"]
}

mdc_defender_plan_is_on_metadata := {
    "Policy Code": "PR-AZR-CLD-MDC-001",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Microsoft Defender for Cloud Defender plans should be set to On",
    "Policy Description": "This policy identifies Azure Microsoft Defender for Cloud which has a Defender setting set to Off. Enabling Azure Defender provides advanced security capabilities like providing threat intelligence, anomaly detection, and behavior analytics in the Azure Microsoft Defender for Cloud. It is highly recommended to enable Azure Defender for all Azure services.",
    "Resource Type": "Microsoft.Security/pricings",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.security/pricings?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/azure/templates/microsoft.security/pricings?pivots=deployment-language-arm-template
# https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/list?tabs=HTTP
#
# PR-AZR-CLD-MDC-002
#

default mdc_defender_plan_is_on_for_app_services = null

azure_attribute_absence["mdc_defender_plan_is_on_for_app_services"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "appservices"
    not resource.properties.pricingTier
}

azure_issue["mdc_defender_plan_is_on_for_app_services"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "appservices"
    lower(resource.properties.pricingTier) != "standard"
}

mdc_defender_plan_is_on_for_app_services {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "appservices"
    not azure_issue["mdc_defender_plan_is_on_for_app_services"]
    not azure_attribute_absence["mdc_defender_plan_is_on_for_app_services"]
}

mdc_defender_plan_is_on_for_app_services = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "appservices"
    azure_issue["mdc_defender_plan_is_on_for_app_services"]
}

mdc_defender_plan_is_on_for_app_services = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "appservices"
    azure_attribute_absence["mdc_defender_plan_is_on_for_app_services"]
}

mdc_defender_plan_is_on_for_app_services_err = "Azure Microsoft Defender for Cloud is currently not set to On for App Services" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "appservices"
    azure_issue["mdc_defender_plan_is_on_for_app_services"]
} else = "microsoft.security/pricings attribute pricingTier is missing from the resource for App Services" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "appservices"
    azure_attribute_absence["mdc_defender_plan_is_on_for_app_services"]
}

mdc_defender_plan_is_on_for_app_services_metadata := {
    "Policy Code": "PR-AZR-CLD-MDC-002",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Microsoft Defender for Cloud should be set to On for App Services",
    "Policy Description": "This policy identifies Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) which has defender setting for App Service is set to Off. Enabling Microsoft Defender for Cloud provides the tools needed to harden your resources, track your security posture, protect against cyberattacks, and streamline security management. It is highly recommended to enable Microsoft Defender for App Service.",
    "Resource Type": "Microsoft.Security/pricings",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.security/pricings?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/azure/templates/microsoft.security/pricings?pivots=deployment-language-arm-template
# https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/list?tabs=HTTP
#
# PR-AZR-CLD-MDC-003
#

default mdc_defender_plan_is_on_for_azure_sql_databases = null

azure_attribute_absence["mdc_defender_plan_is_on_for_azure_sql_databases"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "sqlservers"
    not resource.properties.pricingTier
}

azure_issue["mdc_defender_plan_is_on_for_azure_sql_databases"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "sqlservers"
    lower(resource.properties.pricingTier) != "standard"
}

mdc_defender_plan_is_on_for_azure_sql_databases {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "sqlservers"
    not azure_issue["mdc_defender_plan_is_on_for_azure_sql_databases"]
    not azure_attribute_absence["mdc_defender_plan_is_on_for_azure_sql_databases"]
}

mdc_defender_plan_is_on_for_azure_sql_databases = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "sqlservers"
    azure_issue["mdc_defender_plan_is_on_for_azure_sql_databases"]
}

mdc_defender_plan_is_on_for_azure_sql_databases = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "sqlservers"
    azure_attribute_absence["mdc_defender_plan_is_on_for_azure_sql_databases"]
}

mdc_defender_plan_is_on_for_azure_sql_databases_err = "Azure Microsoft Defender for Cloud is currently not set to On for Azure SQL Databases" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "sqlservers"
    azure_issue["mdc_defender_plan_is_on_for_azure_sql_databases"]
} else = "microsoft.security/pricings attribute pricingTier is missing from the resource for Azure SQL Databases" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "sqlservers"
    azure_attribute_absence["mdc_defender_plan_is_on_for_azure_sql_databases"]
}

mdc_defender_plan_is_on_for_azure_sql_databases_metadata := {
    "Policy Code": "PR-AZR-CLD-MDC-003",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Microsoft Defender for Cloud should be set to On for Azure SQL Databases",
    "Policy Description": "This policy identifies Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) which has defender setting for Azure SQL Databases is set to Off. Enabling Microsoft Defender for Cloud provides the tools needed to harden your resources, track your security posture, protect against cyberattacks, and streamline security management. It is highly recommended to enable Microsoft Defender for Azure SQL Databases.",
    "Resource Type": "Microsoft.Security/pricings",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.security/pricings?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/azure/templates/microsoft.security/pricings?pivots=deployment-language-arm-template
# https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/list?tabs=HTTP
#
# PR-AZR-CLD-MDC-004
#

default mdc_defender_plan_is_on_for_key_vault = null

azure_attribute_absence["mdc_defender_plan_is_on_for_key_vault"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "keyvaults"
    not resource.properties.pricingTier
}

azure_issue["mdc_defender_plan_is_on_for_key_vault"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "keyvaults"
    lower(resource.properties.pricingTier) != "standard"
}

mdc_defender_plan_is_on_for_key_vault {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "keyvaults"
    not azure_issue["mdc_defender_plan_is_on_for_key_vault"]
    not azure_attribute_absence["mdc_defender_plan_is_on_for_key_vault"]
}

mdc_defender_plan_is_on_for_key_vault = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "keyvaults"
    azure_issue["mdc_defender_plan_is_on_for_key_vault"]
}

mdc_defender_plan_is_on_for_key_vault = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "keyvaults"
    azure_attribute_absence["mdc_defender_plan_is_on_for_key_vault"]
}

mdc_defender_plan_is_on_for_key_vault_err = "Azure Microsoft Defender for Cloud is currently not set to On for Key Vault" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "keyvaults"
    azure_issue["mdc_defender_plan_is_on_for_key_vault"]
} else = "microsoft.security/pricings attribute pricingTier is missing from the resource for Key Vault" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "keyvaults"
    azure_attribute_absence["mdc_defender_plan_is_on_for_key_vault"]
}

mdc_defender_plan_is_on_for_key_vault_metadata := {
    "Policy Code": "PR-AZR-CLD-MDC-004",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Microsoft Defender for Cloud should be set to On for Key Vault",
    "Policy Description": "This policy identifies Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) which has defender setting for Azure Key Vault is set to Off. Enabling Microsoft Defender for Cloud provides the tools needed to harden your resources, track your security posture, protect against cyberattacks, and streamline security management. It is highly recommended to enable Microsoft Defender for Azure Key Vault.",
    "Resource Type": "Microsoft.Security/pricings",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.security/pricings?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/azure/templates/microsoft.security/pricings?pivots=deployment-language-arm-template
# https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/list?tabs=HTTP
#
# PR-AZR-CLD-MDC-005
#

default mdc_defender_plan_is_on_for_azure_sql_vm = null

azure_attribute_absence["mdc_defender_plan_is_on_for_azure_sql_vm"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "sqlservervirtualmachines"
    not resource.properties.pricingTier
}

azure_issue["mdc_defender_plan_is_on_for_azure_sql_vm"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "sqlservervirtualmachines"
    lower(resource.properties.pricingTier) != "standard"
}

mdc_defender_plan_is_on_for_azure_sql_vm {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "sqlservervirtualmachines"
    not azure_issue["mdc_defender_plan_is_on_for_azure_sql_vm"]
    not azure_attribute_absence["mdc_defender_plan_is_on_for_azure_sql_vm"]
}

mdc_defender_plan_is_on_for_azure_sql_vm = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "sqlservervirtualmachines"
    azure_issue["mdc_defender_plan_is_on_for_azure_sql_vm"]
}

mdc_defender_plan_is_on_for_azure_sql_vm = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "sqlservervirtualmachines"
    azure_attribute_absence["mdc_defender_plan_is_on_for_azure_sql_vm"]
}

mdc_defender_plan_is_on_for_azure_sql_vm_err = "Azure Microsoft Defender for Cloud is currently not set to On for SQL VM" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "sqlservervirtualmachines"
    azure_issue["mdc_defender_plan_is_on_for_azure_sql_vm"]
} else = "microsoft.security/pricings attribute pricingTier is missing from the resource for SQL VM" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "sqlservervirtualmachines"
    azure_attribute_absence["mdc_defender_plan_is_on_for_azure_sql_vm"]
}

mdc_defender_plan_is_on_for_azure_sql_vm_metadata := {
    "Policy Code": "PR-AZR-CLD-MDC-005",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Microsoft Defender for Cloud should be set to On for SQL VM",
    "Policy Description": "This policy identifies Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) which has defender setting for Azure SQL VM is set to Off. Enabling Microsoft Defender for Cloud provides the tools needed to harden your resources, track your security posture, protect against cyberattacks, and streamline security management. It is highly recommended to enable Microsoft Defender for Azure SQL VM.",
    "Resource Type": "Microsoft.Security/pricings",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.security/pricings?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/azure/templates/microsoft.security/pricings?pivots=deployment-language-arm-template
# https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/list?tabs=HTTP
#
# PR-AZR-CLD-MDC-006
#

default mdc_defender_plan_is_on_for_azure_vm = null

azure_attribute_absence["mdc_defender_plan_is_on_for_azure_vm"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "virtualmachines"
    not resource.properties.pricingTier
}

azure_issue["mdc_defender_plan_is_on_for_azure_vm"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "virtualmachines"
    lower(resource.properties.pricingTier) != "standard"
}

mdc_defender_plan_is_on_for_azure_vm {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "virtualmachines"
    not azure_issue["mdc_defender_plan_is_on_for_azure_vm"]
    not azure_attribute_absence["mdc_defender_plan_is_on_for_azure_vm"]
}

mdc_defender_plan_is_on_for_azure_vm = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "virtualmachines"
    azure_issue["mdc_defender_plan_is_on_for_azure_vm"]
}

mdc_defender_plan_is_on_for_azure_vm = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "virtualmachines"
    azure_attribute_absence["mdc_defender_plan_is_on_for_azure_vm"]
}

mdc_defender_plan_is_on_for_azure_vm_err = "Azure Microsoft Defender for Cloud is currently not set to On for VMs" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "virtualmachines"
    azure_issue["mdc_defender_plan_is_on_for_azure_vm"]
} else = "microsoft.security/pricings attribute pricingTier is missing from the resource for VMs" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "virtualmachines"
    azure_attribute_absence["mdc_defender_plan_is_on_for_azure_vm"]
}

mdc_defender_plan_is_on_for_azure_vm_metadata := {
    "Policy Code": "PR-AZR-CLD-MDC-006",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Microsoft Defender for Cloud should be set to On for VMs",
    "Policy Description": "This policy identifies Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) which has defender setting for Azure VM is set to Off. Enabling Microsoft Defender for Cloud provides the tools needed to harden your resources, track your security posture, protect against cyberattacks, and streamline security management. It is highly recommended to enable Microsoft Defender for Azure VM.",
    "Resource Type": "Microsoft.Security/pricings",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.security/pricings?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/azure/templates/microsoft.security/pricings?pivots=deployment-language-arm-template
# https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/list?tabs=HTTP
#
# PR-AZR-CLD-MDC-007
#

default mdc_defender_plan_is_on_for_azure_storage = null

azure_attribute_absence["mdc_defender_plan_is_on_for_azure_storage"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "storageaccounts"
    not resource.properties.pricingTier
}

azure_issue["mdc_defender_plan_is_on_for_azure_storage"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "storageaccounts"
    lower(resource.properties.pricingTier) != "standard"
}

mdc_defender_plan_is_on_for_azure_storage {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "storageaccounts"
    not azure_issue["mdc_defender_plan_is_on_for_azure_storage"]
    not azure_attribute_absence["mdc_defender_plan_is_on_for_azure_storage"]
}

mdc_defender_plan_is_on_for_azure_storage = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "storageaccounts"
    azure_issue["mdc_defender_plan_is_on_for_azure_storage"]
}

mdc_defender_plan_is_on_for_azure_storage = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "storageaccounts"
    azure_attribute_absence["mdc_defender_plan_is_on_for_azure_storage"]
}

mdc_defender_plan_is_on_for_azure_storage_err = "Azure Microsoft Defender for Cloud is currently not set to On for Storage" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "storageaccounts"
    azure_issue["mdc_defender_plan_is_on_for_azure_storage"]
} else = "microsoft.security/pricings attribute pricingTier is missing from the resource for Storage" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "storageaccounts"
    azure_attribute_absence["mdc_defender_plan_is_on_for_azure_storage"]
}

mdc_defender_plan_is_on_for_azure_storage_metadata := {
    "Policy Code": "PR-AZR-CLD-MDC-007",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Microsoft Defender for Cloud should be set to On for Storage",
    "Policy Description": "This policy identifies Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) which has defender setting for Azure Storage is set to Off. Enabling Microsoft Defender for Cloud provides the tools needed to harden your resources, track your security posture, protect against cyberattacks, and streamline security management. It is highly recommended to enable Microsoft Defender for Azure Storage.",
    "Resource Type": "Microsoft.Security/pricings",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.security/pricings?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/azure/templates/microsoft.security/pricings?pivots=deployment-language-arm-template
# https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/list?tabs=HTTP
#
# PR-AZR-CLD-MDC-008
#

default mdc_defender_plan_is_on_for_azure_containers = null

azure_attribute_absence["mdc_defender_plan_is_on_for_azure_containers"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "containers"
    not resource.properties.pricingTier
}

azure_issue["mdc_defender_plan_is_on_for_azure_containers"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "containers"
    lower(resource.properties.pricingTier) != "standard"
}

mdc_defender_plan_is_on_for_azure_containers {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "containers"
    not azure_issue["mdc_defender_plan_is_on_for_azure_containers"]
    not azure_attribute_absence["mdc_defender_plan_is_on_for_azure_containers"]
}

mdc_defender_plan_is_on_for_azure_containers = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "containers"
    azure_issue["mdc_defender_plan_is_on_for_azure_containers"]
}

mdc_defender_plan_is_on_for_azure_containers = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "containers"
    azure_attribute_absence["mdc_defender_plan_is_on_for_azure_containers"]
}

mdc_defender_plan_is_on_for_azure_containers_err = "Azure Microsoft Defender for Cloud is currently not set to On for Containers" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "containers"
    azure_issue["mdc_defender_plan_is_on_for_azure_containers"]
} else = "microsoft.security/pricings attribute pricingTier is missing from the resource for Containers" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/pricings"
    lower(resource.name) == "containers"
    azure_attribute_absence["mdc_defender_plan_is_on_for_azure_containers"]
}

mdc_defender_plan_is_on_for_azure_containers_metadata := {
    "Policy Code": "PR-AZR-CLD-MDC-008",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Microsoft Defender for Cloud should be set to On for Containers",
    "Policy Description": "This policy identifies Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) which has defender setting for Azure Containers is set to Off. Enabling Microsoft Defender for Cloud provides the tools needed to harden your resources, track your security posture, protect against cyberattacks, and streamline security management. It is highly recommended to enable Microsoft Defender for Azure Containers.",
    "Resource Type": "Microsoft.Security/pricings",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.security/pricings?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/azure/templates/microsoft.security/settings?pivots=deployment-language-arm-template
# https://learn.microsoft.com/en-us/rest/api/defenderforcloud/settings/list?tabs=HTTP#code-try-0
#
# PR-AZR-CLD-MDC-009
#

default mdc_defender_mcas_integration_enabled = null

azure_attribute_absence["mdc_defender_mcas_integration_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/settings"
    lower(resource.name) == "mcas"
    not has_property(resource.properties, "enabled")
}

azure_issue["mdc_defender_mcas_integration_enabled"] {
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.security/settings";
              lower(r.name) == "mcas"
              r.properties.enabled == true;
              c := 1]) == 0
}

mdc_defender_mcas_integration_enabled {
    lower(input.resources[_].type) == "microsoft.security/settings"
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
} else = "microsoft.security/settings attribute enabled is missing from the resource for MCAS integration" {
    azure_attribute_absence["mdc_defender_mcas_integration_enabled"]
}

mdc_defender_mcas_integration_enabled_metadata := {
    "Policy Code": "PR-AZR-CLD-MDC-009",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Microsoft Defender for Cloud MCAS integration should be enabled",
    "Policy Description": "This policy identifies Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) which has Microsoft Defender for Cloud Apps (MCAS) integration disabled. Enabling Microsoft Defender for Cloud provides the tools needed to harden your resources, track your security posture, protect against cyberattacks, and streamline security management. It is highly recommended to enable Microsoft Defender for MCAS.",
    "Resource Type": "Microsoft.Security/settings",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.security/settings?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/azure/templates/microsoft.security/settings?pivots=deployment-language-arm-template
# https://learn.microsoft.com/en-us/rest/api/defenderforcloud/settings/list?tabs=HTTP#code-try-0
#
# PR-AZR-CLD-MDC-010
#

default mdc_defender_wdatp_integration_enabled = null

azure_attribute_absence["mdc_defender_wdatp_integration_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/settings"
    lower(resource.name) == "wdatp"
    not has_property(resource.properties, "enabled")
}

azure_issue["mdc_defender_wdatp_integration_enabled"] {
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.security/settings";
              lower(r.name) == "wdatp"
              r.properties.enabled == true;
              c := 1]) == 0
}

mdc_defender_wdatp_integration_enabled {
    lower(input.resources[_].type) == "microsoft.security/settings"
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
} else = "microsoft.security/settings attribute enabled is missing from the resource for WDATP integration" {
    azure_attribute_absence["mdc_defender_wdatp_integration_enabled"]
}

mdc_defender_wdatp_integration_enabled_metadata := {
    "Policy Code": "PR-AZR-CLD-MDC-010",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Microsoft Defender for Cloud WDATP integration should be enabled",
    "Policy Description": "This policy identifies Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) which has Microsoft Defender for Cloud Apps (WDATP) integration disabled. Enabling Microsoft Defender for Cloud provides the tools needed to harden your resources, track your security posture, protect against cyberattacks, and streamline security management. It is highly recommended to enable Microsoft Defender for WDATP.",
    "Resource Type": "Microsoft.Security/settings",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.security/settings?pivots=deployment-language-arm-template"
}



# https://learn.microsoft.com/sr-cyrl-rs/azure/templates/microsoft.security/autoprovisioningsettings?pivots=deployment-language-arm-template
# https://learn.microsoft.com/en-us/rest/api/defenderforcloud/auto-provisioning-settings/list?tabs=HTTP#code-try-0
#
# PR-AZR-CLD-MDC-011
#

default mdc_defender_provisioning_of_log_analytics_agent_for_vm_is_on = null

azure_attribute_absence["mdc_defender_provisioning_of_log_analytics_agent_for_vm_is_on"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/autoprovisioningsettings"
    lower(resource.name) == "default"
    not resource.properties.autoProvision
}

azure_issue["mdc_defender_provisioning_of_log_analytics_agent_for_vm_is_on"] {
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.security/autoprovisioningsettings";
              lower(r.name) == "default"
              lower(r.properties.autoProvision) == "on";
              c := 1]) == 0
}

mdc_defender_provisioning_of_log_analytics_agent_for_vm_is_on {
    lower(input.resources[_].type) == "microsoft.security/autoprovisioningsettings"
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
} else = "microsoft.security/autoprovisioningsettings attribute autoProvision is missing from the resource for default settings" {
    azure_attribute_absence["mdc_defender_provisioning_of_log_analytics_agent_for_vm_is_on"]
}

mdc_defender_provisioning_of_log_analytics_agent_for_vm_is_on_metadata := {
    "Policy Code": "PR-AZR-CLD-MDC-011",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Microsoft Defender for Cloud automatic provisioning of log Analytics agent for Azure VMs should be turned on",
    "Policy Description": "This policy identifies the Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) which has automatic provisioning of log Analytics agent for Azure VMs is set to Off. Microsoft Defender for Cloud provisions the Microsoft Monitoring Agent on all existing supported Azure virtual machines and any new ones that are created. The Microsoft Monitoring Agent scans for various security-related configurations and events such as system updates, OS vulnerabilities, endpoint protection, and provides alerts.",
    "Resource Type": "Microsoft.Security/autoProvisioningSettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/sr-cyrl-rs/azure/templates/microsoft.security/autoprovisioningsettings?pivots=deployment-language-arm-template"
}



# https://learn.microsoft.com/en-us/azure/templates/microsoft.security/securitycontacts?pivots=deployment-language-arm-template
# https://learn.microsoft.com/en-us/rest/api/defenderforcloud/security-contacts/list?tabs=HTTP
#
# PR-AZR-CLD-MDC-012
#

default mdc_defender_security_alert_email_notification_is_on = null

# azure_attribute_absence["mdc_defender_security_alert_email_notification_is_on"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.security/securitycontacts"
#     not resource.properties.emails
# }

azure_attribute_absence["mdc_defender_security_alert_email_notification_is_on"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/securitycontacts"
    not resource.properties.alertNotifications
}

azure_attribute_absence["mdc_defender_security_alert_email_notification_is_on"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/securitycontacts"
    alertNotifications := resource.properties.alertNotifications
    not alertNotifications.state
}

# azure_issue["mdc_defender_security_alert_email_notification_is_on"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.security/securitycontacts"
#     count(resource.properties.emails) == 0
# }

azure_issue["mdc_defender_security_alert_email_notification_is_on"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/securitycontacts"
    alertNotifications := resource.properties.alertNotifications
    lower(alertNotifications.state) != "on"
}

mdc_defender_security_alert_email_notification_is_on {
    lower(input.resources[_].type) == "microsoft.security/securitycontacts"
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
} else = "Microsoft.Security/securityContacts attribute alertNotifications.state is missing from the resource" {
    azure_attribute_absence["mdc_defender_security_alert_email_notification_is_on"]
}

mdc_defender_security_alert_email_notification_is_on_metadata := {
    "Policy Code": "PR-AZR-CLD-MDC-012",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Microsoft Defender for Cloud security alert email notifications should be set to On",
    "Policy Description": "This policy identifies the Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) which have not set security alert email notifications. Enabling security alert emails ensures that security alert emails are received from Microsoft. This ensures that the right people are aware of any potential security issues and are able to mitigate the risk.",
    "Resource Type": "Microsoft.Security/securityContacts",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.security/securitycontacts?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/azure/templates/microsoft.security/securitycontacts?pivots=deployment-language-arm-template
# https://learn.microsoft.com/en-us/rest/api/defenderforcloud/security-contacts/list?tabs=HTTP
#
# PR-AZR-CLD-MDC-013
#

default mdc_defender_security_alert_email_notification_for_subscription_owner_is_on = null

# azure_attribute_absence["mdc_defender_security_alert_email_notification_for_subscription_owner_is_on"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.security/securitycontacts"
#     not resource.properties.emails
# }

azure_attribute_absence["mdc_defender_security_alert_email_notification_for_subscription_owner_is_on"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/securitycontacts"
    not resource.properties.notificationsByRole
}

azure_attribute_absence["mdc_defender_security_alert_email_notification_for_subscription_owner_is_on"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/securitycontacts"
    notificationsByRole := resource.properties.notificationsByRole
    not notificationsByRole.state
}

azure_attribute_absence["mdc_defender_security_alert_email_notification_for_subscription_owner_is_on"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/securitycontacts"
    notificationsByRole := resource.properties.notificationsByRole
    not notificationsByRole.roles
}

# azure_issue["mdc_defender_security_alert_email_notification_for_subscription_owner_is_on"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.security/securitycontacts"
#     count(resource.properties.emails) == 0
# }

azure_issue["mdc_defender_security_alert_email_notification_for_subscription_owner_is_on"] {
     count([c | r := input.resources[_];
              lower(r.type) == "microsoft.security/securitycontacts";
              array_contains(r.properties.notificationsByRole.roles, "Owner");
              lower(r.properties.notificationsByRole.state) == "on";
              c := 1]) == 0
}

mdc_defender_security_alert_email_notification_for_subscription_owner_is_on {
    lower(input.resources[_].type) == "microsoft.security/securitycontacts"
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
} else = "Microsoft.Security/securityContacts attribute notificationsByRole.state or notificationsByRole.roles or both are missing from the resource" {
    azure_attribute_absence["mdc_defender_security_alert_email_notification_for_subscription_owner_is_on"]
}

mdc_defender_security_alert_email_notification_for_subscription_owner_is_on_metadata := {
    "Policy Code": "PR-AZR-CLD-MDC-013",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Microsoft Defender for Cloud email notification for subscription owner should be set to On",
    "Policy Description": "This policy identifies the Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) in which email notification for subscription owners is not set. Enabling security alert emails to subscription owners ensures that they receive security alert emails from Microsoft. This ensures that they are aware of any potential security issues and can mitigate the risk in a timely fashion.",
    "Resource Type": "Microsoft.Security/securityContacts",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.security/securitycontacts?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/azure/templates/microsoft.security/securitycontacts?pivots=deployment-language-arm-template
# https://learn.microsoft.com/en-us/rest/api/defenderforcloud/security-contacts/list?tabs=HTTP
#
# PR-AZR-CLD-MDC-014
#

default mdc_defender_security_contact_additional_email_is_set = null

azure_attribute_absence["mdc_defender_security_contact_additional_email_is_set"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/securitycontacts"
    not resource.properties.emails
}

azure_issue["mdc_defender_security_contact_additional_email_is_set"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.security/securitycontacts"
    count(resource.properties.emails) == 0
}

mdc_defender_security_contact_additional_email_is_set {
    lower(input.resources[_].type) == "microsoft.security/securitycontacts"
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
} else = "Microsoft.Security/securityContacts attribute emails is missing from the resource" {
    azure_attribute_absence["mdc_defender_security_contact_additional_email_is_set"]
}

mdc_defender_security_contact_additional_email_is_set_metadata := {
    "Policy Code": "PR-AZR-CLD-MDC-014",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Microsoft Defender for Cloud security contact additional email should be set",
    "Policy Description": "This policy identifies the Azure Microsoft Defender for Cloud (previously known as Azure Security Center and Azure Defender) which has not set security contact additional email addresses. Microsoft Defender for Cloud emails the subscription owners whenever a high-severity alert is triggered for their subscription. Providing a security contact email address as an additional email address ensures that the proper people are aware of any potential compromise in order to mitigate the risk in a timely fashion.",
    "Resource Type": "Microsoft.Security/securityContacts",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.security/securitycontacts?pivots=deployment-language-arm-template"
}



