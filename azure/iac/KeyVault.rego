package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults

# PR-AZR-ARM-KV-001

default KeyVault = null

azure_attribute_absence["KeyVault"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    accessPolicy := resource.properties.accessPolicies[_]
    not accessPolicy.permissions.keys
    not accessPolicy.permissions.secrets
    not accessPolicy.permissions.certificates
    not accessPolicy.permissions.storage
}

source_path[{"KeyVault":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.keyvault/vaults"
    accessPolicy := resource.properties.accessPolicies[j]
    not accessPolicy.permissions.keys
    not accessPolicy.permissions.secrets
    not accessPolicy.permissions.certificates
    not accessPolicy.permissions.storage
    metadata:= {
        "resource_path": [["resources",i,"properties","accessPolicies",j,"permissions"]]
    }
}


azure_issue["KeyVault"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    accessPolicy := resource.properties.accessPolicies[_]
    count(accessPolicy.permissions.keys) == 0
    count(accessPolicy.permissions.secrets) == 0
    count(accessPolicy.permissions.certificates) == 0
    count(accessPolicy.permissions.storage) == 0
}

source_path[{"KeyVault":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.keyvault/vaults"
    accessPolicy := resource.properties.accessPolicies[j]
    count(accessPolicy.permissions.keys) == 0
    count(accessPolicy.permissions.secrets) == 0
    count(accessPolicy.permissions.certificates) == 0
    count(accessPolicy.permissions.storage) == 0
    metadata:= {
        "resource_path": [["resources",i,"properties","accessPolicies",j,"permissions"]]
    }
}

KeyVault {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    not azure_attribute_absence["KeyVault"]
    not azure_issue["KeyVault"]
}

KeyVault = false {
    azure_issue["KeyVault"]
}

KeyVault = false {
    azure_attribute_absence["KeyVault"]
}

KeyVault_err = "accessPolicy property 'permissions.keys' or 'permissions.secrets' or 'permissions.certificates' or 'permissions.storage' is missing from the microsoft.keyvault/vaults resource." {
    azure_attribute_absence["KeyVault"]
} else = "Currently no principal has access to Keyvault" {
    azure_issue["KeyVault"]
}

KeyVault_metadata := {
    "Policy Code": "PR-AZR-ARM-KV-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure at least one principal has access to Keyvault",
    "Policy Description": "Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.",
    "Resource Type": "microsoft.keyvault/vaults",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults"
}



# PR-AZR-ARM-KV-002

default enableSoftDelete = null
azure_attribute_absence ["enableSoftDelete"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    not resource.properties.enableSoftDelete
}

source_path[{"enableSoftDelete":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.keyvault/vaults"
    not resource.properties.enableSoftDelete
    metadata:= {
        "resource_path": [["resources",i,"properties","enableSoftDelete"]]
    }
}

azure_issue ["enableSoftDelete"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    resource.properties.enableSoftDelete != true
}

source_path[{"enableSoftDelete":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.keyvault/vaults"
    resource.properties.enableSoftDelete != true
    metadata:= {
        "resource_path": [["resources",i,"properties","enableSoftDelete"]]
    }
}

enableSoftDelete {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    not azure_attribute_absence["enableSoftDelete"]
    not azure_issue["enableSoftDelete"]
}

enableSoftDelete = false {
    azure_issue["enableSoftDelete"]
}

enableSoftDelete {
    azure_attribute_absence["enableSoftDelete"]
    not azure_issue["enableSoftDelete"]
}

enableSoftDelete_err = "'Soft Delete' setting is currently not enabled for Key Vault" {
    azure_issue["enableSoftDelete"]
}

enableSoftDelete_metadata := {
    "Policy Code": "PR-AZR-ARM-KV-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault",
    "Policy Description": "The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, KV databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.",
    "Resource Type": "microsoft.keyvault/vaults",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults"
}



# PR-AZR-ARM-KV-003

default enablePurgeProtection = null

azure_attribute_absence ["enablePurgeProtection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    not resource.properties.enablePurgeProtection
}

source_path[{"enablePurgeProtection":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.keyvault/vaults"
    not resource.properties.enablePurgeProtection
    metadata:= {
        "resource_path": [["resources",i,"properties","enablePurgeProtection"]]
    }
}

azure_issue ["enablePurgeProtection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    resource.properties.enablePurgeProtection != true
}

source_path[{"enablePurgeProtection":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.keyvault/vaults"
    resource.properties.enablePurgeProtection != true
    metadata:= {
        "resource_path": [["resources",i,"properties","enablePurgeProtection"]]
    }
}

enablePurgeProtection {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    not azure_attribute_absence["enablePurgeProtection"]
    not azure_issue["enablePurgeProtection"]
}

enablePurgeProtection = false {
    azure_issue["enablePurgeProtection"]
}

enablePurgeProtection = false {
    azure_attribute_absence["enablePurgeProtection"]
}

enablePurgeProtection_err = "microsoft.keyvault/vaults resoruce property enablePurgeProtection is missing" {
    azure_attribute_absence["enableSoftDelete"]
} else = "Purge protection is currently not enabled on Key vault" {
    azure_issue["enableSoftDelete"]
}

enablePurgeProtection_metadata := {
    "Policy Code": "PR-AZR-ARM-KV-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Key vault should have purge protection enabled",
    "Policy Description": "The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation",
    "Resource Type": "microsoft.keyvault/vaults",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults"
}


# PR-AZR-ARM-KV-006

default keyvault_Acl = null

azure_attribute_absence ["keyvault_Acl"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    not resource.properties.networkAcls.defaultAction
}

source_path[{"keyvault_Acl":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.keyvault/vaults"
    not resource.properties.networkAcls.defaultAction
    metadata:= {
        "resource_path": [["resources",i,"properties","networkAcls","defaultAction"]]
    }
}

azure_issue ["keyvault_Acl"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    lower(resource.properties.networkAcls.defaultAction) != "deny"
}

source_path[{"keyvault_Acl":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.keyvault/vaults"
    lower(resource.properties.networkAcls.defaultAction) != "deny"
    metadata:= {
        "resource_path": [["resources",i,"properties","networkAcls","defaultAction"]]
    }
}

keyvault_Acl {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    not azure_attribute_absence["keyvault_Acl"]
    not azure_issue["keyvault_Acl"]
}

keyvault_Acl = false {
    azure_issue["keyvault_Acl"]
}

keyvault_Acl = false {
    azure_attribute_absence["keyvault_Acl"]
}

keyvault_Acl_err = "microsoft.keyvault/vaults resoruce property 'networkAcls.defaultAction' is missing" {
    azure_attribute_absence["keyvault_Acl"]
} else = "Azure Key Vault enabled for public network access" {
    azure_issue["keyvault_Acl"]
}

keyvault_Acl_metadata := {
    "Policy Code": "PR-AZR-ARM-KV-006",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Key Vault should disable public network access",
    "Policy Description": "Disable public network access for your key vault so that it's not accessible over the public internet. This can reduce data leakage risks.",
    "Resource Type": "microsoft.keyvault/vaults",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults"
}


# PR-AZR-ARM-KV-007

default keyvault_bypass = null

azure_attribute_absence ["keyvault_bypass"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    not resource.properties.networkAcls.bypass
}

source_path[{"keyvault_bypass":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.keyvault/vaults"
    not resource.properties.networkAcls.bypass
    metadata:= {
        "resource_path": [["resources",i,"properties","networkAcls","bypass"]]
    }
}

azure_issue ["keyvault_bypass"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    lower(resource.properties.networkAcls.bypass) != "azureservices"
}

source_path[{"keyvault_bypass":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.keyvault/vaults"
    lower(resource.properties.networkAcls.bypass) != "azureservices"
    metadata:= {
        "resource_path": [["resources",i,"properties","networkAcls","bypass"]]
    }
}

keyvault_bypass {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    not azure_attribute_absence["keyvault_bypass"]
    not azure_issue["keyvault_bypass"]
}

keyvault_bypass = false {
    azure_issue["keyvault_bypass"]
}

keyvault_bypass = false {
    azure_attribute_absence["keyvault_bypass"]
}

keyvault_bypass_err = "microsoft.keyvault/vaults resoruce property 'networkAcls.bypass' is missing" {
    azure_attribute_absence["keyvault_bypass"]
} else = "Azure Key Vault Trusted Microsoft Services access is not enabled" {
    azure_issue["keyvault_bypass"]
}

keyvault_bypass_metadata := {
    "Policy Code": "PR-AZR-ARM-KV-007",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Key Vault Trusted Microsoft Services access should be enabled",
    "Policy Description": "Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.",
    "Resource Type": "microsoft.keyvault/vaults",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults"
}


# PR-AZR-ARM-KV-008

default keyvault_service_endpoint = null

azure_attribute_absence ["keyvault_service_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    virtualNetworkRule := resource.properties.networkAcls.virtualNetworkRules[_]
    not virtualNetworkRule.id
}

source_path[{"keyvault_service_endpoint":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.keyvault/vaults"
    virtualNetworkRule := resource.properties.networkAcls.virtualNetworkRules[j]
    not virtualNetworkRule.id
    metadata:= {
        "resource_path": [["resources",i,"properties","networkAcls","virtualNetworkRules",j,"id"]]
    }
}

azure_attribute_absence ["keyvault_service_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    not resource.properties.networkAcls.virtualNetworkRules
}

source_path[{"keyvault_service_endpoint":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.keyvault/vaults"
    virtualNetworkRule := resource.properties.networkAcls.virtualNetworkRules
    metadata:= {
        "resource_path": [["resources",i,"properties","networkAcls","virtualNetworkRules"]]
    }
}

azure_issue ["keyvault_service_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    virtualNetworkRule := resource.properties.networkAcls.virtualNetworkRules[_]
    count(virtualNetworkRule.id) == 0
}

source_path[{"keyvault_service_endpoint":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.keyvault/vaults"
    virtualNetworkRule := resource.properties.networkAcls.virtualNetworkRules[j]
    count(virtualNetworkRule.id) == 0
    metadata:= {
        "resource_path": [["resources",i,"properties","networkAcls","virtualNetworkRules",j,"id"]]
    }
}

keyvault_service_endpoint {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    not azure_attribute_absence["keyvault_service_endpoint"]
    not azure_issue["keyvault_service_endpoint"]
}

keyvault_service_endpoint = false {
    azure_attribute_absence["keyvault_service_endpoint"]
}

keyvault_service_endpoint = false {
    azure_issue["keyvault_service_endpoint"]
}

keyvault_service_endpoint_err = "microsoft.keyvault/vaults resoruce property 'networkAcls.virtualNetworkRules' or 'networkAcls.virtualNetworkRules.id' are missing" {
    azure_attribute_absence["keyvault_service_endpoint"]
} else = "Service Endpoint disabled for Azure Key Vault" {
    azure_issue["keyvault_service_endpoint"]
}

keyvault_service_endpoint_metadata := {
    "Policy Code": "PR-AZR-ARM-KV-008",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Key Vault should use a virtual network service endpoint",
    "Policy Description": "This policy audits any Key Vault not configured to use a virtual network service endpoint.",
    "Resource Type": "microsoft.keyvault/vaults",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults"
}


# PR-AZR-ARM-KV-009
#

default kv_private_endpoint = null

azure_attribute_absence["kv_private_endpoint"] {
    count([c | lower(input.resources[_].type) == "microsoft.network/privateendpoints"; c := 1]) == 0 
}

no_azure_issue["kv_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/privateendpoints"
    privateLinkServiceConnection := resource.properties.privateLinkServiceConnections[_]
    contains(lower(privateLinkServiceConnection.properties.privateLinkServiceId), "microsoft.keyvault/vaults")
}

source_path[{"kv_private_endpoint":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.network/privateendpoints"
    privateLinkServiceConnection := resource.properties.privateLinkServiceConnections[j]
    contains(lower(privateLinkServiceConnection.properties.privateLinkServiceId), "microsoft.keyvault/vaults")
    metadata:= {
        "resource_path": [["resources",i,"properties","privateLinkServiceConnections",j,"properties","privateLinkServiceId"]]
    }
}

kv_private_endpoint {
	lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    no_azure_issue["kv_private_endpoint"]
    not azure_attribute_absence["kv_private_endpoint"]
}

kv_private_endpoint = false {
	lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    not no_azure_issue["kv_private_endpoint"]
}

kv_private_endpoint = false {
	lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    azure_attribute_absence["kv_private_endpoint"]
}

kv_private_endpoint_err = "Azure Key Vault does not configure with private endpoints" {
	lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    not no_azure_issue["kv_private_endpoint"]
} else = "Azure Private endpoints resoruce is missing" {
	lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    azure_attribute_absence["kv_private_endpoint"]
}

kv_private_endpoint_metadata := {
    "Policy Code": "PR-AZR-ARM-KV-009",
    "Type": "IaC",  
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Key Vault should use private link",
    "Policy Description": "Azure Private Link lets you connect your virtual network to Azure services without a public IP address at the source or destination. The Private Link platform handles the connectivity between the consumer and services over the Azure backbone network. By mapping private endpoints to your key vault, data leakage risks are reduced. Learn more about private links at - https://aka.ms/azureprivatelinkoverview",
    "Resource Type": "microsoft.keyvault/vaults",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults"
}



# PR-AZR-ARM-KV-010

default kv_public_access_disabled = null

azure_attribute_absence["kv_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    not resource.properties.publicNetworkAccess
}

source_path[{"kv_public_access_disabled":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.keyvault/vaults"
    not resource.properties.publicNetworkAccess
    metadata:= {
        "resource_path": [["resources",i,"properties","publicNetworkAccess"]]
    }
}

azure_issue["kv_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    lower(resource.properties.publicNetworkAccess) != "disabled"
}

source_path[{"kv_public_access_disabled":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.keyvault/vaults"
    lower(resource.properties.publicNetworkAccess) != "disabled"
    metadata:= {
        "resource_path": [["resources",i,"properties","publicNetworkAccess"]]
    }
}

kv_public_access_disabled {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    not azure_attribute_absence["kv_public_access_disabled"]
    not azure_issue["kv_public_access_disabled"]
}

kv_public_access_disabled = false {
    azure_attribute_absence["kv_public_access_disabled"]
}

kv_public_access_disabled = false {
    azure_issue["kv_public_access_disabled"]
}

kv_public_access_disabled_err = "Public Network Access is currently not disabled on Azure KeyVault." {
    azure_issue["kv_public_access_disabled"]
} else = "public network access property is missing from the resource." {
    azure_attribute_absence["kv_public_access_disabled"]
}


kv_public_access_disabled_metadata := {
    "Policy Code": "PR-AZR-ARM-KV-010",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure Azure KeyVault don't have public network access enabled",
    "Policy Description": "Always use Private Endpoint for Azure KeyVault",
    "Resource Type": "microsoft.keyvault/vaults",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults"
}