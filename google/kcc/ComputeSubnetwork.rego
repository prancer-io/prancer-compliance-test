package rule

# https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computesubnetwork

#
# PRIVATE_GOOGLE_ACCESS_DISABLED
# PR-GCP-0034-KCC

default private_google_access_disabled = null


gc_issue["private_google_access_disabled"] {
    lower(input.kind) == "computesubnetwork"
    not input.spec.privateIpGoogleAccess
}

private_google_access_disabled {
    lower(input.kind) == "computesubnetwork"
    not gc_issue["private_google_access_disabled"]
}

private_google_access_disabled = false {
    gc_issue["private_google_access_disabled"]
}

private_google_access_disabled_err = "There are private subnetworks without access to Google public APIs." {
    gc_issue["private_google_access_disabled"]
}

private_google_access_disabled_metadata := {
    "Policy Code": "PRIVATE_GOOGLE_ACCESS_DISABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Bucket CMEK Disabled",
    "Policy Description": "There are private subnetworks without access to Google public APIs.",
    "Resource Type": "ComputeSubnetwork",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computesubnetwork"
}
