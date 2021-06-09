package rule

# https://docs.microsoft.com/en-us/azure/templates/azurerm_container_registry_webhook

#
# PR-AZR-0005-TRF
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
    not azure_issue["acr_webhooks"]
    not azure_attribute_absence["acr_webhooks"]
}

acr_webhooks = false {
    azure_issue["acr_webhooks"]
}

acr_webhooks = false {
    azure_attribute_absence["acr_webhooks"]
}

acr_webhooks_err = "Azure ACR HTTPS not enabled for webhook" {
    azure_issue["acr_webhooks"]
}

acr_webhooks_miss_err = "Container registy webhook attribute service_uri missing in the resource" {
    azure_attribute_absence["acr_webhooks"]
}

acr_webhooks_metadata := {
    "Policy Code": "PR-AZR-0005-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure ACR HTTPS not enabled for webhook",
    "Policy Description": "Ensure you send container registry webhooks only to a HTTPS endpoint. This policy checks your container registry webhooks and alerts if it finds a URI with HTTP.",
    "Compliance": [],
    "Resource Type": "azurerm_container_registry_webhook",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/azurerm_container_registry_webhook"
}
