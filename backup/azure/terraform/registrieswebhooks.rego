package rule

# https://docs.microsoft.com/en-us/azure/templates/azurerm_container_registry_webhook
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_registry_webhook
#
# PR-AZR-TRF-ACR-001
#

default acr_webhooks = null

azure_attribute_absence["acr_webhooks"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry_webhook"
    not resource.properties.service_uri
}

azure_issue["acr_webhooks"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry_webhook"
    substring(lower(resource.properties.service_uri), 0, 6) != "https:"
}

acr_webhooks {
    lower(input.resources[_].type) == "azurerm_container_registry_webhook"
    not azure_attribute_absence["acr_webhooks"]
    not azure_issue["acr_webhooks"]
}

acr_webhooks = false {
    azure_attribute_absence["acr_webhooks"]
}

acr_webhooks = false {
    azure_issue["acr_webhooks"]
}


acr_webhooks_err = "azurerm_container_registry_webhook property 'service_uri' need to be exist. Its missing from the resource." {
    azure_attribute_absence["acr_webhooks"]
} else = "Azure ACR currently does not have HTTPS protocol enabled for webhook" {
    azure_issue["acr_webhooks"]
}

acr_webhooks_metadata := {
    "Policy Code": "PR-AZR-TRF-ACR-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure ACR should have HTTPS protocol enabled for webhook",
    "Policy Description": "Ensure you send container registry webhooks only to a HTTPS endpoint. This policy checks your container registry webhooks and alerts if it finds a URI with HTTP.",
    "Resource Type": "azurerm_container_registry_webhook",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_registry_webhook"
}
