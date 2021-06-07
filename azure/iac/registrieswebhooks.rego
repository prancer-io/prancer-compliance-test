package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries/webhooks

#
# PR-AZR-0005-ARM
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

acr_webhooks_metadata := {
    "Policy Code": "PR-AZR-0005-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure ACR HTTPS not enabled for webhook",
    "Policy Description": "Ensure you send container registry webhooks only to a HTTPS endpoint. This policy checks your container registry webhooks and alerts if it finds a URI with HTTP.",
    "Resource Type": "microsoft.containerregistry/registries/webhooks",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries/webhooks"
}
