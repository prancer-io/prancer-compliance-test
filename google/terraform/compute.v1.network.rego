package rule

# https://cloud.google.com/compute/docs/reference/rest/v1/networks

#
# PR-GCP-TRF-NET-001
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
    "Policy Code": "PR-GCP-TRF-NET-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP project is configured with legacy network",
    "Policy Description": "This policy identifies the projects which have configured with legacy networks. Legacy networks have a single network IPv4 prefix range and a single gateway IP address for the whole network. Subnetworks cannot be created in a legacy network. Legacy networks can have an impact on high network traffic projects and subject to the single point of failure.",
    "Resource Type": "google_compute_network",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/networks"
}


#
# PR-GCP-TRF-NET-002
#

default net_default = null

gc_issue["net_default"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project"
    resource.properties.auto_create_network != false
}

net_default {
    lower(input.resources[_].type) == "google_project"
    not gc_issue["net_default"]
}

net_default = false {
    gc_issue["net_default"]
}

net_default_err = "GCP project is using the default network" {
    gc_issue["net_default"]
}

net_default_metadata := {
    "Policy Code": "PR-GCP-TRF-NET-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP project is using the default network",
    "Policy Description": "This policy identifies the projects which have default network configured. It is recommended to use network configuration based on your security and networking requirements, you should create your network and delete the default network.",
    "Resource Type": "google_project",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects"
}
