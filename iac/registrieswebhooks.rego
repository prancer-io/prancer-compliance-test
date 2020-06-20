package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries/webhooks

#
# Azure ACR HTTPS not enabled for webhook (214)
#

default acr_webhooks = null

acr_webhooks {
    input.type == "Microsoft.ContainerRegistry/registries/webhooks"
    substring(lower(input.properties.serviceUri), 0, 6) == "https:"
}

acr_webhooks = false {
    input.type == "Microsoft.ContainerRegistry/registries/webhooks"
    substring(lower(input.properties.serviceUri), 0, 6) != "https:"
}

acr_webhooks_err = "Azure ACR HTTPS not enabled for webhook" {
	acr_webhooks == false
}
