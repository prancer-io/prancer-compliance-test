package rule

# https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computenetwork

#
# DEFAULT_NETWORK
#

default default_network = null

gc_issue["default_network"] {
    lower(input.kind) == "computenetwork"
    lower(input.metadata.name) == "default"
}

default_network {
    lower(input.kind) == "computenetwork"
    not gc_issue["default_network"]
}

default_network = false {
    gc_issue["default_network"]
}

default_network_err = "The default network exists in a project." {
    gc_issue["default_network"]
}

default_network_metadata := {
    "Policy Code": "DEFAULT_NETWORK",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Default Network",
    "Policy Description": "The default network exists in a project.",
    "Resource Type": "ComputeNetwork",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computenetwork"
}

#
# LEGACY_NETWORK
#

default legacy_network = null

gc_issue["legacy_network"] {
    lower(input.kind) == "computenetwork"
    input.spec.IPv4Range
}

legacy_network {
    lower(input.kind) == "computenetwork"
    not gc_issue["legacy_network"]
}

legacy_network = false {
    gc_issue["legacy_network"]
}

legacy_network_err = "A legacy network exists in a project." {
    gc_issue["legacy_network"]
}

legacy_network_metadata := {
    "Policy Code": "LEGACY_NETWORK",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Default Network",
    "Policy Description": "A legacy network exists in a project.",
    "Resource Type": "ComputeNetwork",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computenetwork"
}
