package rule

# https://cloud.google.com/compute/docs/reference/rest/v1/networks

#
# PR-GCP-0076-GDF
#

default net_legacy = null

gc_issue["net_legacy"] {
    resource := input.resources[_]
    lower(resource.type) == "compute.v1.network"
    not resource.properties.autoCreateSubnetworks
}

net_legacy {
    lower(input.resources[_].type) == "compute.v1.network"
    not gc_issue["net_legacy"]
}

net_legacy = false {
    gc_issue["net_legacy"]
}

net_legacy_err = "GCP project is configured with legacy network" {
    gc_issue["net_legacy"]
}

net_legacy_metadata := {
    "Policy Code": "PR-GCP-0076-GDF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP project is configured with legacy network",
    "Policy Description": "This policy identifies the projects which have configured with legacy networks. Legacy networks have a single network IPv4 prefix range and a single gateway IP address for the whole network. Subnetworks cannot be created in a legacy network. Legacy networks can have an impact on high network traffic projects and subject to the single point of failure.",
    "Resource Type": "compute.v1.network",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/networks"
}

#
# PR-GCP-0077-GDF
#

default net_default = null


gc_attribute_absence["net_default"] {
    resource := input.resources[_]
    lower(resource.type) == "compute.v1.network"
    not resource.properties.name
}

gc_issue["net_default"] {
    resource := input.resources[_]
    lower(resource.type) == "compute.v1.network"
    lower(resource.properties.name) == "default"
}

net_default {
    lower(input.resources[_].type) == "compute.v1.network"
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

net_default_err = "GCP network attribute name missing in the resource" {
    gc_attribute_absence["net_default"]
}

net_default_metadata := {
    "Policy Code": "PR-GCP-0077-GDF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP project is using the default network",
    "Policy Description": "This policy identifies the projects which have default network configured. It is recommended to use network configuration based on your security and networking requirements, you should create your network and delete the default network.",
    "Resource Type": "compute.v1.network",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/networks"
}
