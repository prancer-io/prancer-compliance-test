package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries/webhooks

#
# Azure ACR HTTPS not enabled for webhook (214)
#

default acr_webhooks = null

azure_attribute_absence["acr_webhooks"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries/webhooks"
    not resource.properties.serviceUri
}

azure_issue["acr_webhooks"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries/webhooks"
    substring(lower(resource.properties.serviceUri), 0, 6) != "https:"
}

acr_webhooks {
    lower(input.resources[_].type) == "microsoft.containerregistry/registries/webhooks"
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

acr_webhooks_miss_err = "Container registy webhook attribute serviceUri missing in the resource" {
    azure_attribute_absence["acr_webhooks"]
}
