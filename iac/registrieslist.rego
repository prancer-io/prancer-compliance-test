package rule

# https://docs.microsoft.com/en-us/rest/api/containerregistry/registries/list

#
# Azure Container Registry using the deprecated classic registry (224)
#

default acr_classic = null

acr_classic {
    count([ c | lower(input.value[i].type) == "microsoft.containerregistry/registries";
             lower(input.value[i].sku.name) == "classic";
             c := 1]) == 0
}

acr_classic = false {
    count([ c | lower(input.value[i].type) == "microsoft.containerregistry/registries";
             lower(input.value[i].sku.name) == "classic";
             c := 1]) > 0
}

acr_classic_err = "Azure Container Registry using the deprecated classic registry" {
    acr_classic == false
}
