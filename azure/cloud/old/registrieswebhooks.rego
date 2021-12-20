package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries/webhooks

#
# PR-AZR-ACR-001
#

default acr_webhooks = null

azure_attribute_absence["acr_webhooks"] {
    not input.properties.serviceUri
}

azure_issue["acr_webhooks"] {
    substring(lower(input.properties.serviceUri), 0, 6) != "https:"
}

acr_webhooks {
    not azure_attribute_absence["acr_webhooks"]
    not azure_issue["acr_webhooks"]
}

acr_webhooks = false {
    azure_issue["acr_webhooks"]
}

acr_webhooks = false {
    azure_attribute_absence["acr_webhooks"]
}

acr_webhooks_err = "Azure ACR webhook currently dont have HTTPS protocol enabled" {
    azure_issue["acr_webhooks"]
} else = "ACR webhook property 'serviceUri' is missing from the resource" {
    azure_attribute_absence["acr_webhooks"]
}

acr_webhooks_metadata := {
    "Policy Code": "PR-AZR-ACR-001",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure ACR should have HTTPS protocol enabled for webhook",
    "Policy Description": "Ensure you send container registry webhooks only to a HTTPS endpoint. This policy checks your container registry webhooks and alerts if it finds a URI with HTTP.",
    "Resource Type": "microsoft.containerregistry/registries/webhooks",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries/webhooks"
}
