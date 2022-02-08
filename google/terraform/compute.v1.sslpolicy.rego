package rego

#
# PR-GCP-TRF-INST-009
#

default compute_ssl_profile_restricted = null

gc_issue["compute_ssl_profile_restricted"] {
    resource := input.resources[i]
    lower(resource.type) == "google_compute_ssl_policy"
    lower(resource.properties.profile) != "custom"
    lower(resource.properties.profile) != "restricted"
}

compute_ssl_profile_restricted {
    lower(input.resources[i].type) == "google_compute_ssl_policy"
    not gc_issue["compute_ssl_profile_restricted"]
}

compute_ssl_profile_restricted = false {
    gc_issue["compute_ssl_profile_restricted"]
}

compute_ssl_profile_restricted_err = "Ensure GCP HTTPS Load balancer SSL Policy is using restrictive profile" {
    gc_issue["compute_ssl_profile_restricted"]
}

compute_ssl_profile_restricted_metadata := {
    "Policy Code": "PR-GCP-TRF-INST-009",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP HTTPS Load balancer SSL Policy is using restrictive profile",
    "Policy Description": "This policy identifies HTTPS Load balancers which are not using restrictive profile in it's SSL Policy, which controls sets of features used in negotiating SSL with clients. As a best security practice, use RESTRICTED as SSL policy profile as it meets stricter compliance requirements and does not include any out-of-date SSL features.",
    "Resource Type": "google_compute_ssl_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}


#
# PR-GCP-TRF-INST-010
#

deprecated_min_tls_version = ["tls_1_0", "tls_1_1"]

default compute_ssl_min_tls = null

gc_issue["compute_ssl_min_tls"] {
    resource := input.resources[i]
    lower(resource.type) == "google_compute_ssl_policy"
    lower(resource.properties.min_tls_version) == deprecated_min_tls_version[_]
}

compute_ssl_min_tls {
    lower(input.resources[i].type) == "google_compute_ssl_policy"
    not gc_issue["compute_ssl_min_tls"]
}

compute_ssl_min_tls = false {
    gc_issue["compute_ssl_min_tls"]
}

compute_ssl_min_tls_err = "Ensure GCP HTTPS Load balancer is configured with SSL policy not having TLS version 1.1 or lower" {
    gc_issue["compute_ssl_min_tls"]
}

compute_ssl_min_tls_metadata := {
    "Policy Code": "PR-GCP-TRF-INST-010",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure GCP HTTPS Load balancer is configured with SSL policy not having TLS version 1.1 or lower",
    "Policy Description": "This policy identifies HTTPS Load balancers is configured with SSL policy having TLS version 1.1 or lower. As a best security practice, use TLS 1.2 as the minimum TLS version in your load balancers SSL security policies.",
    "Resource Type": "google_compute_ssl_policy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}
