package rule

# https://cloud.google.com/compute/docs/reference/rest/v1/networks

#
# PR-GCP-0076-TRF
#

default net_legacy = null

gc_issue["net_legacy"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_network"
    not resource.properties.auto_create_subnetworks
}

gc_issue["net_legacy"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_network"
    resource.properties.auto_create_subnetworks == null
}

net_legacy {
    lower(input.resources[_].type) == "google_compute_network"
    not gc_issue["net_legacy"]
}

net_legacy = false {
    gc_issue["net_legacy"]
}

net_legacy_err = "GCP project is configured with legacy network" {
    gc_issue["net_legacy"]
}

net_legacy_metadata := {
    "Policy Code": "PR-GCP-0076-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP project is configured with legacy network",
    "Policy Description": "This policy identifies the projects which have configured with legacy networks. Legacy networks have a single network IPv4 prefix range and a single gateway IP address for the whole network. Subnetworks cannot be created in a legacy network. Legacy networks can have an impact on high network traffic projects and subject to the single point of failure.",
    "Resource Type": "google_compute_network",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/networks"
}
