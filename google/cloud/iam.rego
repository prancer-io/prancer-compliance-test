package rule

https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts.keys

#
# PR-GCP-CLD-SAK-001
#

default svc_account_key = null


gc_attribute_absence["svc_account_key"] {
    # lower(resource.type) == "iam.v1.serviceaccounts.key"
    not input.name
}

source_path[{"svc_account_key": metadata}] {
    # lower(resource.type) == "iam.v1.serviceaccounts.key"
    not input.name
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "name"]
        ],
    }
}

gc_issue["svc_account_key"] {
    # lower(resource.type) == "iam.v1.serviceaccounts.key"
    contains(lower(input.name), "iam.gserviceaccount.com")
    time.now_ns() - time.parse_rfc3339_ns(input.validAfterTime) > 7776000000000000
}

source_path[{"svc_account_key": metadata}] {
    # lower(resource.type) == "iam.v1.serviceaccounts.key"
    contains(lower(input.name), "iam.gserviceaccount.com")
    time.now_ns() - time.parse_rfc3339_ns(input.validAfterTime) > 7776000000000000
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "validAfterTime"]
        ],
    }
}


svc_account_key {
    # lower(input.resources[i].type) == "iam.v1.serviceaccounts.key"
    not gc_issue["svc_account_key"]
    not gc_attribute_absence["svc_account_key"]
}

svc_account_key = false {
    gc_issue["svc_account_key"]
}

svc_account_key = false {
    gc_attribute_absence["svc_account_key"]
}

svc_account_key_err = "GCP User managed service account keys are not rotated for 90 days" {
    gc_issue["svc_account_key"]
}

svc_account_key_miss_err = "GCP User managed service account keys attribute name missing in the resource" {
    gc_attribute_absence["svc_account_key"]
}

svc_account_key_metadata := {
    "Policy Code": "PR-GCP-CLD-SAK-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP User managed service account keys are not rotated for 90 days",
    "Policy Description": "This policy identifies user-managed service account keys which are not rotated from last 90 days or more. Rotating Service Account keys will reduce the window of opportunity for an access key that is associated with a compromised or terminated account to be used. Service Account keys should be rotated to ensure that data cannot be accessed with an old key which might have been lost, cracked, or stolen. It is recommended that all user-managed service account keys are regularly rotated.",
    "Resource Type": "iam.v1.serviceaccounts.key",
    "Policy Help URL": "",
    # "Resource Help URL": "https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts.keys"
}


#
# PR-GCP-CLD-SAK-002
#
#  "iam.v1.projects"

default non_gcp_account_access_denied = null

gc_issue["non_gcp_account_access_denied"] {
    not contains(lower(input.bindings[_].members[_]), "gserviceaccount.com")
    
}

non_gcp_account_access_denied {
    not gc_issue["non_gcp_account_access_denied"]
}

non_gcp_account_access_denied = false {
    gc_issue["non_gcp_account_access_denied"]
}

non_gcp_account_access_denied_err = "Ensure, Non-corporate accounts have access to Google Cloud Platform (GCP) resources." {
    gc_issue["non_gcp_account_access_denied"]
}

non_gcp_account_access_denied_metadata := {
    "Policy Code": "PR-GCP-CLD-SAK-002",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure, Non-corporate accounts have access to Google Cloud Platform (GCP) resources.",
    "Policy Description": "Ensure, using personal accounts to access GCP resources may compromise the security of your business. Using fully managed corporate Google accounts to access Google Cloud Platform resources is recommended to make sure that your resources are secure. NOTE : This policy requires customization before using it. To customize, follow the steps mentioned: (1) Clone this policy and replace '@yourcompanydomainname' in RQL with your domain name. For example: 'user does not end with @prismacloud.io and user does not end with gserviceaccount.com'. (2) For multiple domains, update the RQL with conditions for each domain. For example: 'user does not end with @prismacloud.io and user does not end with @prismacloud.com and user does not end with gserviceaccount.com'.",
    "Resource Type": "iam.v1.projects",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects"
}


#
# PR-GCP-CLD-SAK-003
#
#  "iam.v1.projects"

default admin_privileges_enabled = null

gc_issue["admin_privileges_enabled"] {

    contains(lower(input.bindings[_].members[_]), "iam.gserviceaccount.com")
    contains(lower(input.bindings[_].role), "admin")
}

gc_issue["admin_privileges_enabled"] {

    contains(lower(input.bindings[_].members[_]), "iam.gserviceaccount.com")
    contains(lower(input.bindings[_].role), "Admin")
}
gc_issue["admin_privileges_enabled"] {

    contains(lower(input.bindings[_].members[_]), "iam.gserviceaccount.com")
    contains(lower(input.bindings[_].role), "roles/editor")
}
gc_issue["admin_privileges_enabled"] {

    contains(lower(input.bindings[_].members[_]), "iam.gserviceaccount.com")
    contains(lower(input.bindings[_].role), "roles/owner")   
}


admin_privileges_enabled {
    not gc_issue["admin_privileges_enabled"]
}

admin_privileges_enabled = false {
    gc_issue["admin_privileges_enabled"]
}

admin_privileges_enabled_err = "Ensure, GCP IAM Service account has admin privileges." {
    gc_issue["admin_privileges_enabled"]
}

admin_privileges_enabled_metadata := {
    "Policy Code": "PR-GCP-CLD-SAK-003",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure, GCP IAM Service account has admin privileges.",
    "Policy Description": "Ensure, service accounts which have admin privileges. Application uses the service account to make requests to the Google API of a service so that the users aren't directly involved. It is recommended not to use admin access for ServiceAccount.",
    "Resource Type": "iam.v1.projects",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects"
}