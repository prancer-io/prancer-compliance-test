package rule

# https://cloud.google.com/compute/docs/reference/rest/v1/firewalls

#
# Id: 269
#

default svc_account_key = null


gc_attribute_absence["svc_account_key"] {
    resource := input.json.resources[_]
    lower(resource.type) == "compute.v1.firewall"
    not resource.properties.name
}

gc_issue["svc_account_key"] {
    resource := input.json.resources[_]
    lower(resource.type) == "compute.v1.firewall"
    lower(resource.properties.name) == "default-allow-ssh"
    resource.properties.sourceRanges[_] == "0.0.0.0/0"
}

gc_issue["svc_account_key"] {
    resource := input.json.resources[_]
    lower(resource.type) == "compute.v1.firewall"
    lower(resource.properties.name) == "default-allow-icmp"
    resource.properties.sourceRanges[_] == "0.0.0.0/0"
}

gc_issue["svc_account_key"] {
    resource := input.json.resources[_]
    lower(resource.type) == "compute.v1.firewall"
    lower(resource.properties.name) == "default-allow-internal"
    resource.properties.sourceRanges[_] == "0.0.0.0/0"
}

gc_issue["svc_account_key"] {
    resource := input.json.resources[_]
    lower(resource.type) == "compute.v1.firewall"
    lower(resource.properties.name) == "default-allow-rdp"
    resource.properties.sourceRanges[_] == "0.0.0.0/0"
}

svc_account_key {
    lower(input.json.resources[_].type) == "compute.v1.firewall"
    not gc_issue["svc_account_key"]
    not gc_attribute_absence["svc_account_key"]
}

svc_account_key = false {
    gc_issue["svc_account_key"]
}

svc_account_key = false {
    gc_attribute_absence["svc_account_key"]
}

svc_account_key_err = "Default Firewall rule should not have any rules (except http and https)" {
    gc_issue["svc_account_key"]
}

svc_account_key_miss_err = "GCP vm firewall attribute name missing in the resource" {
    gc_attribute_absence["svc_account_key"]
}

