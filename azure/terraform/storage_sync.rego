package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_sync
# PR-AZR-TRF-STS-001
#

default storage_sync_public_network_access_disabled = null

azure_attribute_absence["storage_sync_public_network_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_sync"
    not resource.properties.incoming_traffic_policy
}

azure_issue["storage_sync_public_network_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_storage_sync"
    lower(resource.properties.incoming_traffic_policy) != "allowvirtualnetworksonly"
}

storage_sync_public_network_access_disabled {
    lower(input.resources[_].type) == "azurerm_storage_sync"
    not azure_attribute_absence["storage_sync_public_network_access_disabled"]
    not azure_issue["storage_sync_public_network_access_disabled"]
}

storage_sync_public_network_access_disabled = false {
    azure_attribute_absence["storage_sync_public_network_access_disabled"]
}

storage_sync_public_network_access_disabled = false {
    azure_issue["storage_sync_public_network_access_disabled"]
}

storage_sync_public_network_access_disabled_err = "azurerm_storage_sync property 'incoming_traffic_policy' is missing from the resource" {
    azure_attribute_absence["storage_sync_public_network_access_disabled"]
} else = "Public network access currently not disabled for Azure File Sync" {
    azure_issue["storage_sync_public_network_access_disabled"]
}

storage_sync_public_network_access_disabled_metadata := {
    "Policy Code": "PR-AZR-TRF-STS-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Public network access should be disabled for Azure File Sync",
    "Policy Description": "Disabling the public endpoint allows you to restrict access to your Storage Sync Service resource to requests destined to approved private endpoints on your organization's network. There is nothing inherently insecure about allowing requests to the public endpoint, however, you may wish to disable it to meet regulatory, legal, or organizational policy requirements. You can disable the public endpoint for a Storage Sync Service by setting the incomingTrafficPolicy of the resource to AllowVirtualNetworksOnly.",
    "Resource Type": "azurerm_storage_sync",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_sync"
}