
#
# PR-GCP-TRF-SAK-002
#
google_project_iam = ["google_project_iam_policy", "google_project_iam_binding", "google_project_iam_member"]

default non_gcp_account_access_denied = null

gc_issue["non_gcp_account_access_denied"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_policy"
    bindings := resource.properties.binding[_]
    not contains(lower(bindings.members[_]), "gserviceaccount.com")
}

gc_issue["non_gcp_account_access_denied"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_policy"
    bindings := resource.properties.binding[_]
    not contains(lower(bindings.member[_]), "gserviceaccount.com")
}

gc_issue["non_gcp_account_access_denied"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_binding"
    bindings := resource.properties
    not contains(lower(bindings.members[_]), "gserviceaccount.com")
}

gc_issue["non_gcp_account_access_denied"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_binding"
    bindings := resource.properties
    not contains(lower(bindings.member[_]), "gserviceaccount.com")
}

gc_issue["non_gcp_account_access_denied"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_member"
    bindings := resource.properties
    not contains(lower(bindings.members), "gserviceaccount.com")
}

gc_issue["non_gcp_account_access_denied"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_member"
    bindings := resource.properties
    not contains(lower(bindings.member), "gserviceaccount.com")
}

non_gcp_account_access_denied {
    lower(input.resources[_].type) == google_project_iam[_]
    not gc_issue["non_gcp_account_access_denied"]
}

non_gcp_account_access_denied = false {
    gc_issue["non_gcp_account_access_denied"]
}

non_gcp_account_access_denied_err = "Ensure, Non-corporate accounts have access to Google Cloud Platform (GCP) resources." {
    gc_issue["non_gcp_account_access_denied"]
}

non_gcp_account_access_denied_metadata := {
    "Policy Code": "PR-GCP-TRF-SAK-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure, Non-corporate accounts have access to Google Cloud Platform (GCP) resources.",
    "Policy Description": "Ensure, using personal accounts to access GCP resources may compromise the security of your business. Using fully managed corporate Google accounts to access Google Cloud Platform resources is recommended to make sure that your resources are secure. NOTE : This policy requires customization before using it. To customize, follow the steps mentioned: (1) Clone this policy and replace '@yourcompanydomainname' in RQL with your domain name. For example: 'user does not end with @prismacloud.io and user does not end with gserviceaccount.com'. (2) For multiple domains, update the RQL with conditions for each domain. For example: 'user does not end with @prismacloud.io and user does not end with @prismacloud.com and user does not end with gserviceaccount.com'.",
    "Resource Type": "google_project_iam_policy", "google_project_iam_binding", "google_project_iam_member"
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects"
}


#
# PR-GCP-TRF-SAK-003
#

default admin_privileges_enabled = null

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_policy"
    bindings := resource.properties.binding[_]
    contains(lower(bindings.members[_]), "iam.gserviceaccount.com")
    contains(lower(bindings.role), "admin")
}

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_policy"
    bindings := resource.properties.binding[_]
    contains(lower(bindings.members[_]), "iam.gserviceaccount.com")
    contains(lower(bindings.role), "roles/owner")
}

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_policy"
    bindings := resource.properties.binding[_]
    contains(lower(bindings.members[_]), "iam.gserviceaccount.com")
    contains(lower(bindings.role), "Admin")
}

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_policy"
    bindings := resource.properties.binding[_]
    contains(lower(bindings.members[_]), "iam.gserviceaccount.com")
    contains(lower(bindings.role), "roles/editor")
}

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_policy"
    bindings := resource.properties.binding[_]
    contains(lower(bindings.member[_]), "iam.gserviceaccount.com")
    contains(lower(bindings.role), "Admin")
}

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_policy"
    bindings := resource.properties.binding[_]
    contains(lower(bindings.member[_]), "iam.gserviceaccount.com")
    contains(lower(bindings.role), "roles/owner")
}

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_policy"
    bindings := resource.properties.binding[_]
    contains(lower(bindings.member[_]), "iam.gserviceaccount.com")
    contains(lower(bindings.role), "roles/editor")
}

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_policy"
    bindings := resource.properties.binding[_]
    contains(lower(bindings.member[_]), "iam.gserviceaccount.com")
    contains(lower(bindings.role), "admin")
}

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_binding"
    bindings := resource.properties
    contains(lower(bindings.members[_]), "iam.gserviceaccount.com")
    contains(lower(bindings.role), "roles/editor")
}

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_binding"
    bindings := resource.properties
    contains(lower(bindings.members[_]), "iam.gserviceaccount.com")
    contains(lower(bindings.role), "roles/owner")
}

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_binding"
    bindings := resource.properties
    contains(lower(bindings.members[_]), "iam.gserviceaccount.com")
    contains(lower(bindings.role), "Admin")
}

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_binding"
    bindings := resource.properties
    contains(lower(bindings.members[_]), "iam.gserviceaccount.com")
    contains(lower(bindings.role), "admin")
}

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_binding"
    bindings := resource.properties
    contains(lower(bindings.member[_]), "iam.gserviceaccount.com")
    contains(lower(bindings.role), "roles/owner")
}

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_binding"
    bindings := resource.properties
    contains(lower(bindings.member[_]), "iam.gserviceaccount.com")
    contains(lower(bindings.role), "roles/editor")
}

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_binding"
    bindings := resource.properties
    contains(lower(bindings.member[_]), "iam.gserviceaccount.com")
    contains(lower(bindings.role), "Admin")
}

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_binding"
    bindings := resource.properties
    contains(lower(bindings.member[_]), "iam.gserviceaccount.com")
    contains(lower(bindings.role), "admin")
}

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_member"
    bindings := resource.properties
    contains(lower(bindings.members), "iam.gserviceaccount.com")
    contains(lower(bindings.role), "admin")
}

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_member"
    bindings := resource.properties
    contains(lower(bindings.members), "iam.gserviceaccount.com")
    contains(lower(bindings.role), "Admin")
}

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_member"
    bindings := resource.properties
    contains(lower(bindings.members), "iam.gserviceaccount.com")
    contains(lower(bindings.role), "roles/editor")
}

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_member"
    bindings := resource.properties
    contains(lower(bindings.members), "iam.gserviceaccount.com")
    contains(lower(bindings.role), "roles/owner")
}

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_member"
    bindings := resource.properties
    contains(lower(bindings.member), "iam.gserviceaccount.com")
    contains(lower(bindings.role), "Admin")
}

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_member"
    bindings := resource.properties
    contains(lower(bindings.member), "iam.gserviceaccount.com")
    contains(lower(bindings.role), "admin")
}

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_member"
    bindings := resource.properties
    contains(lower(bindings.member), "iam.gserviceaccount.com")
    contains(lower(bindings.role), "roles/editor")
}

gc_issue["admin_privileges_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_member"
    bindings := resource.properties
    contains(lower(bindings.member), "iam.gserviceaccount.com")
    contains(lower(bindings.role), "roles/owner")
}

admin_privileges_enabled {
    lower(input.resources[_].type) == google_project_iam[_]
    not gc_issue["admin_privileges_enabled"]
}

admin_privileges_enabled = false {
    gc_issue["admin_privileges_enabled"]
}

admin_privileges_enabled_err = "Ensure, GCP IAM Service account has admin privileges." {
    gc_issue["admin_privileges_enabled"]
}

admin_privileges_enabled_metadata := {
    "Policy Code": "PR-GCP-TRF-SAK-003",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure, GCP IAM Service account has admin privileges.",
    "Policy Description": "Ensure, service accounts which have admin privileges. Application uses the service account to make requests to the Google API of a service so that the users aren't directly involved. It is recommended not to use admin access for ServiceAccount.",
    "Resource Type": ["google_project_iam_policy", "google_project_iam_binding", "google_project_iam_member"]
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects"
}


