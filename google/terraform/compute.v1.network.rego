package rule

# https://cloud.google.com/compute/docs/reference/rest/v1/networks

#
# PR-GCP-0076-TRF
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
