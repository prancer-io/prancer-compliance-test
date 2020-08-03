package rule

# https://cloud.google.com/compute/docs/reference/rest/v1/networks

#
# Id: 337
#

default net_legacy = null

gc_issue["net_legacy"] {
    resource := input.json.resources[_]
    lower(resource.type) == "compute.v1.network"
    not resource.properties.autoCreateSubnetworks
}

net_legacy {
    lower(input.json.resources[_].type) == "compute.v1.network"
    not gc_issue["net_legacy"]
}

net_legacy = false {
    gc_issue["net_legacy"]
}

net_legacy_err = "GCP project is configured with legacy network" {
    gc_issue["net_legacy"]
}

#
# Id: 338
#

default net_default = null


gc_attribute_absence["net_default"] {
    resource := input.json.resources[_]
    lower(resource.type) == "compute.v1.network"
    not resource.properties.name
}

gc_issue["net_default"] {
    resource := input.json.resources[_]
    lower(resource.type) == "compute.v1.network"
    lower(resource.properties.name) == "default"
}

net_default {
    lower(input.json.resources[_].type) == "compute.v1.network"
    not gc_issue["net_default"]
    not gc_attribute_absence["net_default"]
}

net_default = false {
    gc_issue["net_default"]
}

net_default = false {
    gc_attribute_absence["net_default"]
}

net_default_err = "GCP project is using the default network" {
    gc_issue["net_default"]
}

net_default_miss_err = "GCP network attribute name missing in the resource" {
    gc_attribute_absence["net_default"]
}
