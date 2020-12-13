package rule

# https://docs.microsoft.com/en-us/azure/templates/azurerm_container_registry_webhook

#
# PR-AZR-0005-TRF
#

default acr_webhooks = null

azure_attribute_absence["acr_webhooks"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_container_registry_webhook"
    not resource.properties.service_uri
}

azure_issue["acr_webhooks"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_container_registry_webhook"
    substring(lower(resource.properties.service_uri), 0, 6) != "https:"
}

acr_webhooks {
    lower(input.json.resources[_].type) == "azurerm_container_registry_webhook"
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
