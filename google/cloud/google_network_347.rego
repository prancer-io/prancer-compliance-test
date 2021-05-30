#
# PR-GCP-0077
#

package rule
default rulepass = true

# GCP project is using the default network
# if GCP project is not using the default network

# API and Response Reference : https://cloud.google.com/compute/docs/reference/rest/v1/networks/list

rulepass = false {
    lower(input.type) == "compute.v1.network"
    count(networksname) == 1
}

networksname[input.id] {
    input.name == "default"
}

metadata := {
    "Policy Code": "PR-GCP-0077",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP project is using the default network",
    "Policy Description": "This policy identifies the projects which have default network configured. It is recommended to use network configuration based on your security and networking requirements, you should create your network and delete the default network.",
    "Resource Type": "compute.v1.network",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/networks/list"
}
