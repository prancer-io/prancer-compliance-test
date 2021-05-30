#
# PR-GCP-0076
#

package rule
default rulepass = true

# GCP project is configured with legacy network
# if GCP project is configured with legacy network

# API and Response Reference : https://cloud.google.com/compute/docs/reference/rest/v1/networks/list

rulepass = false {
    lower(input.type) == "compute.v1.network"
    count(networksname) == 1
}

networksname[input.id] {
    input.autoCreateSubnetworks == true
}

metadata := {
    "Policy Code": "PR-GCP-0076",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP project is configured with legacy network",
    "Policy Description": "This policy identifies the projects which have configured with legacy networks. Legacy networks have a single network IPv4 prefix range and a single gateway IP address for the whole network. Subnetworks cannot be created in a legacy network. Legacy networks can have an impact on high network traffic projects and subject to the single point of failure.",
    "Resource Type": "compute.v1.network",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/networks/list"
}
