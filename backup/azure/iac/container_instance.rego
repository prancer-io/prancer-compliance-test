package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

# PR-AZR-ARM-ACI-001

default aci_configured_with_vnet = null

azure_attribute_absence ["aci_configured_with_vnet"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerinstance/containergroups"
    not resource.properties.ipAddress.type
}

azure_issue ["aci_configured_with_vnet"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerinstance/containergroups"
    lower(resource.properties.ipAddress.type) != "private"
}

aci_configured_with_vnet {
    lower(input.resources[_].type) == "microsoft.containerinstance/containergroups"
    not azure_attribute_absence["aci_configured_with_vnet"]
    not azure_issue["aci_configured_with_vnet"]
}

aci_configured_with_vnet = false {
    azure_attribute_absence["aci_configured_with_vnet"]
}

aci_configured_with_vnet = false {
    azure_issue["aci_configured_with_vnet"]
}

aci_configured_with_vnet_err = "Azure Container Instance is currently not configured with virtual network" {
    azure_issue["aci_configured_with_vnet"]
} else = "Azure Container Instance property ipAddress.type is missing from the resource" {
    azure_attribute_absence["aci_configured_with_vnet"] 
}

aci_configured_with_vnet_metadata := {
    "Policy Code": "PR-AZR-ARM-ACI-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure Azure Container Instance is configured with virtual network",
    "Policy Description": "This policy identifies Azure Container Instances (ACI) that are not configured with a virtual network. Making container instances public makes an internet routable network. By deploying container instances into an Azure virtual network, your containers can communicate securely with other resources in the virtual network. So it is recommended to configure all your container instances within a virtual network.<br><br>For more details:<br>https://docs.microsoft.com/en-us/azure/container-instances/container-instances-vnet",
    "Resource Type": "microsoft.containerinstance/containergroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.containerinstance/containergroups?tabs=json&pivots=deployment-language-arm-template"
}


# PR-AZR-ARM-ACI-002

default aci_configured_with_managed_identity = null

azure_attribute_absence ["aci_configured_with_managed_identity"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerinstance/containergroups"
    not resource.identity.type
}

azure_issue ["aci_configured_with_managed_identity"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerinstance/containergroups"
    count(resource.identity.type) == 0
}

azure_issue ["aci_configured_with_managed_identity"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerinstance/containergroups"
    lower(resource.identity.type) == "none"
}

aci_configured_with_managed_identity {
    lower(input.resources[_].type) == "microsoft.containerinstance/containergroups"
    not azure_attribute_absence["aci_configured_with_managed_identity"]
    not azure_issue["aci_configured_with_managed_identity"]
}

aci_configured_with_managed_identity = false {
    azure_attribute_absence["aci_configured_with_managed_identity"]
}

aci_configured_with_managed_identity = false {
    azure_issue["aci_configured_with_managed_identity"]
}

aci_configured_with_managed_identity_err = "Azure Container Instance is currently not configured with managed identity" {
    azure_issue["aci_configured_with_managed_identity"]
} else = "Azure Container Instance identity.type is missing from the resource" {
    azure_attribute_absence["aci_configured_with_managed_identity"] 
}

aci_configured_with_managed_identity_metadata := {
    "Policy Code": "PR-AZR-ARM-ACI-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure Azure Container Instance is configured with managed identity",
    "Policy Description": "This policy identifies Azure Container Instances (ACI) that are not configured with the managed identity. The managed identity is authenticated with Azure AD, developers don't have to store any credentials in code. So It is recommended to configure managed identity on all your container instances.<br><br>For more details:<br>https://docs.microsoft.com/en-us/azure/container-instances/container-instances-managed-identity",
    "Resource Type": "microsoft.containerinstance/containergroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.containerinstance/containergroups?tabs=json&pivots=deployment-language-arm-template"
}


# PR-AZR-ARM-ACI-003

default aci_usage_cmk = null

azure_attribute_absence ["aci_usage_cmk"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerinstance/containergroups"
    not resource.properties.encryptionProperties
}

azure_attribute_absence ["aci_usage_cmk"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerinstance/containergroups"
    not resource.properties.encryptionProperties.vaultBaseUrl
}

azure_issue ["aci_usage_cmk"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerinstance/containergroups"
    count(resource.properties.encryptionProperties.vaultBaseUrl) == 0
}

aci_usage_cmk {
    lower(input.resources[_].type) == "microsoft.containerinstance/containergroups"
    not azure_attribute_absence["aci_usage_cmk"]
    not azure_issue["aci_usage_cmk"]
}

aci_usage_cmk = false {
    azure_attribute_absence["aci_usage_cmk"]
}

aci_usage_cmk = false {
    azure_issue["aci_usage_cmk"]
}

aci_usage_cmk_err = "Azure Container Instance is currently not using custom managed key for encryption" {
    azure_issue["aci_usage_cmk"]
} else = "Azure Container Instance property encryptionProperties.vaultBaseUrl is missing from the resource" {
    azure_attribute_absence["aci_usage_cmk"] 
}

aci_usage_cmk_metadata := {
    "Policy Code": "PR-AZR-ARM-ACI-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure Azure Container Instance usage custom managed key for encryption",
    "Policy Description": "Secure your containers with greater flexibility using customer-managed keys. When you specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. Using customer-managed keys provides additional capabilities to control rotation of the key encryption key or cryptographically erase data.",
    "Resource Type": "microsoft.containerinstance/containergroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.containerinstance/containergroups?tabs=json&pivots=deployment-language-arm-template"
}