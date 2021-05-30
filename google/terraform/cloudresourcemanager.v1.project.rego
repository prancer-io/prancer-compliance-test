package rule

# https://cloud.google.com/resource-manager/reference/rest/v1/projects

#
# PR-GCP-0077-TRF
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
    "Policy Code": "PR-GCP-0077-TRF",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "GCP project is using the default network",
    "Policy Description": "This policy identifies the projects which have default network configured. It is recommended to use network configuration based on your security and networking requirements, you should create your network and delete the default network.",
    "Resource Type": "google_project",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects"
}
