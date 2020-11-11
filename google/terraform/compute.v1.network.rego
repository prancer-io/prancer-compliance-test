package rule

# https://cloud.google.com/compute/docs/reference/rest/v1/networks

#
# Id: 346
#

default net_legacy = null

gc_issue["net_legacy"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_compute_network"
    not resource.properties.auto_create_subnetworks
}

net_legacy {
    lower(input.json.resources[_].type) == "google_compute_network"
    not gc_issue["net_legacy"]
}

net_legacy = false {
    gc_issue["net_legacy"]
}

net_legacy_err = "GCP project is configured with legacy network" {
    gc_issue["net_legacy"]
}

#
# Id: 347
#

default net_default = null


gc_attribute_absence["net_default"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_compute_network"
    not resource.properties.name
}

gc_issue["net_default"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_compute_network"
    lower(resource.properties.name) == "default"
}

net_default {
    lower(input.json.resources[_].type) == "google_compute_network"
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
