package rule

# https://cloud.google.com/compute/docs/reference/rest/v1/targetHttpsProxies

#
# PR-GCP-0057-GDF
#

default lbs_ssl_policy = null

gc_issue["lbs_ssl_policy"] {
    resource := input.resources[_]
    lower(resource.type) == "compute.v1.targethttpsproxy"
    not resource.properties.sslPolicy
}

gc_issue["lbs_ssl_policy"] {
    resource := input.resources[_]
    lower(resource.type) == "compute.v1.targethttpsproxy"
    count(resource.properties.sslPolicy) == 0
}

lbs_ssl_policy {
    lower(input.resources[_].type) == "compute.v1.targethttpsproxy"
    not gc_issue["lbs_ssl_policy"]
}

lbs_ssl_policy = false {
    gc_issue["lbs_ssl_policy"]
}

lbs_ssl_policy_err = "GCP Load balancer HTTPS target proxy configured with default SSL policy instead of custom SSL policy" {
    gc_issue["lbs_ssl_policy"]
}

#
# PR-GCP-0058-GDF
#

default lbs_quic = null

gc_attribute_absence["lbs_quic"] {
    resource := input.resources[_]
    lower(resource.type) == "compute.v1.targethttpsproxy"
    not resource.properties.quicOverride
}

gc_issue["lbs_quic"] {
    resource := input.resources[_]
    lower(resource.type) == "compute.v1.targethttpsproxy"
    lower(resource.properties.quicOverride) != "enable"
}

lbs_quic {
    lower(input.resources[_].type) == "compute.v1.targethttpsproxy"
    not gc_issue["lbs_quic"]
    not gc_attribute_absence["lbs_quic"]
}

lbs_quic = false {
    gc_issue["lbs_quic"]
}

lbs_quic = false {
    gc_attribute_absence["lbs_quic"]
}

lbs_quic_err = "GCP Load balancer HTTPS target proxy is not configured with QUIC protocol" {
    gc_issue["lbs_quic"]
}

lbs_quic_miss_err = "GCP Load balancer attribute quicOverride missing in the resource" {
    gc_attribute_absence["lbs_quic"]
}
