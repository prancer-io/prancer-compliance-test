package rule

# https://cloud.google.com/resource-manager/reference/rest/v1/projects

#
# PR-GCP-0077-TRF
#

default net_default = null

gc_issue["net_default"] {
    resource := input.json.resources[_]
    lower(resource.type) == "google_project"
    resource.properties.auto_create_network != false
}

net_default {
    lower(input.json.resources[_].type) == "google_project"
    not gc_issue["net_default"]
}

net_default = false {
    gc_issue["net_default"]
}

net_default_err = "GCP project is using the default network" {
    gc_issue["net_default"]
}
