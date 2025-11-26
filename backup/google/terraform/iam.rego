package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

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
    "Resource Type": ["google_project_iam_policy", "google_project_iam_binding", "google_project_iam_member"],
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
    contains(lower(bindings.role), "roles/editor")
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
    "Resource Type": ["google_project_iam_policy", "google_project_iam_binding", "google_project_iam_member"],
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects"
}


#
# PR-GCP-TRF-SAK-004
#

default overly_permissive_ac_privileges = null

gc_issue["overly_permissive_ac_privileges"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_policy"
    bindings := resource.properties.binding[_]
    contains(lower(bindings.role), "roles/iam.serviceaccountadmin")
    contains(lower(bindings.role), "roles/iam.serviceaccountuser")
}

gc_issue["overly_permissive_ac_privileges"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_binding"
    bindings := resource.properties
    contains(lower(bindings.role), "roles/iam.serviceaccountadmin")
    contains(lower(bindings.role), "roles/iam.serviceaccountuser")
}

gc_issue["overly_permissive_ac_privileges"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_member"
    bindings := resource.properties
    contains(lower(bindings.role), "roles/iam.serviceaccountadmin")
    contains(lower(bindings.role), "roles/iam.serviceaccountuser")
}

overly_permissive_ac_privileges {
    lower(input.resources[_].type) == google_project_iam[_]
    not gc_issue["overly_permissive_ac_privileges"]
}

overly_permissive_ac_privileges = false {
    gc_issue["overly_permissive_ac_privileges"]
}

overly_permissive_ac_privileges_err = "Ensure, GCP IAM Users have overly permissive service account privileges." {
    gc_issue["overly_permissive_ac_privileges"]
}

overly_permissive_ac_privileges_metadata := {
    "Policy Code": "PR-GCP-TRF-SAK-004",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure, GCP IAM Users have overly permissive service account privileges.",
    "Policy Description": "Ensure, IAM users which have overly permissive service account privileges. Any user should not have Service Account Admin and Service Account User, both roles assigned at a time. Built-in/Predefined IAM role Service Account admin allows the user to create, delete, manage service accounts. Built-in/Predefined IAM role Service Account User allows the user to assign service accounts to Apps/Compute Instances. It is recommended to follow the principle of 'Separation of Duties' ensuring that one individual does not have all the necessary permissions to be able to complete a malicious action or meant to help avoid security or privacy incidents and errors.",
    "Resource Type": ["google_project_iam_policy", "google_project_iam_binding", "google_project_iam_member"],
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects"
}


#
# PR-GCP-TRF-SAK-005
#

default overly_permissive_kms_privileges = null

gc_issue["overly_permissive_kms_privileges"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_policy"
    bindings := resource.properties.binding[_]
    contains(lower(bindings.role), "roles/cloudkms.admin")
    contains(lower(bindings.role), "roles/cloudkms.crypto")
}

gc_issue["overly_permissive_kms_privileges"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_binding"
    bindings := resource.properties
    contains(lower(bindings.role), "roles/cloudkms.admin")
    contains(lower(bindings.role), "roles/cloudkms.crypto")
}

gc_issue["overly_permissive_kms_privileges"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_member"
    bindings := resource.properties
    contains(lower(bindings.role), "roles/cloudkms.admin")
    contains(lower(bindings.role), "roles/cloudkms.crypto")
}

overly_permissive_kms_privileges {
    lower(input.resources[_].type) == google_project_iam[_]
    not gc_issue["overly_permissive_kms_privileges"]
}

overly_permissive_kms_privileges = false {
    gc_issue["overly_permissive_kms_privileges"]
}

overly_permissive_kms_privileges_err = "Ensure, GCP IAM user have overly permissive Cloud KMS roles." {
    gc_issue["overly_permissive_kms_privileges"]
}

overly_permissive_kms_privileges_metadata := {
    "Policy Code": "PR-GCP-TRF-SAK-005",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure, GCP IAM user have overly permissive Cloud KMS roles.",
    "Policy Description": "Ensure, IAM users who have overly permissive Cloud KMS roles. Built-in/Predefined IAM role Cloud KMS Admin allows the user to create, delete, and manage service accounts. Built-in/Predefined IAM role Cloud KMS CryptoKey Encrypter/Decrypter allows the user to encrypt and decrypt data at rest using the encryption keys. It is recommended to follow the principle of 'Separation of Duties' ensuring that one individual does not have all the necessary permissions to be able to complete a malicious action.",
    "Resource Type": ["google_project_iam_policy", "google_project_iam_binding", "google_project_iam_member"],
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects"
}


#
# PR-GCP-TRF-SAK-006
#

default service_ac_privileges = null

gc_issue["service_ac_privileges"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_policy"
    bindings := resource.properties.binding[_]
    contains(lower(bindings.role), "roles/iam.serviceaccountactor")
}

gc_issue["service_ac_privileges"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_policy"
    bindings := resource.properties.binding[_]
    contains(lower(bindings.role), "roles/iam.serviceaccountuser")
}

gc_issue["service_ac_privileges"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_policy"
    bindings := resource.properties.binding[_]
    contains(lower(bindings.role), "roles/iam.serviceaccounttokencreator")
}

gc_issue["service_ac_privileges"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_binding"
    bindings := resource.properties
    contains(lower(bindings.role), "roles/iam.serviceaccountactor")
}

gc_issue["service_ac_privileges"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_binding"
    bindings := resource.properties
    contains(lower(bindings.role), "roles/iam.serviceaccountuser")
}

gc_issue["service_ac_privileges"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_binding"
    bindings := resource.properties
    contains(lower(bindings.role), "roles/iam.serviceaccounttokencreator")
}

gc_issue["service_ac_privileges"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_member"
    bindings := resource.properties
    contains(lower(bindings.role), "roles/iam.serviceaccountactor")
}

gc_issue["service_ac_privileges"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_member"
    bindings := resource.properties
    contains(lower(bindings.role), "roles/iam.serviceaccountuser")
}

gc_issue["service_ac_privileges"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_member"
    bindings := resource.properties
    contains(lower(bindings.role), "roles/iam.serviceaccounttokencreator")
}

service_ac_privileges {
    lower(input.resources[_].type) == google_project_iam[_]
    not gc_issue["service_ac_privileges"]
}

service_ac_privileges = false {
    gc_issue["service_ac_privileges"]
}

service_ac_privileges_err = "Ensure, GCP IAM user with service account privileges." {
    gc_issue["service_ac_privileges"]
}

service_ac_privileges_metadata := {
    "Policy Code": "PR-GCP-TRF-SAK-006",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure, GCP IAM user with service account privileges.",
    "Policy Description": "Ensure, IAM users don't have service account privileges. Adding any user as service account actor will enable these users to have service account privileges. Adding only authorized corporate IAM users as service account actors will make sure that your information is secure.",
    "Resource Type": ["google_project_iam_policy", "google_project_iam_binding", "google_project_iam_member"],
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects"
}


#
# PR-GCP-TRF-SAK-007
# 

list_var = ["appspot.gserviceaccount.com",
            "developer.gserviceaccount.com",
            "cloudservices.gserviceaccount.com",
            "system.gserviceaccount.com",
            "cloudbuild.gserviceaccount.com"]

default iam_primitive_roles_in_use = null

gc_issue["iam_primitive_roles_in_use"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_policy"
	count([c | contains(input.resources[_].properties.binding[_].members[_] , list_var[_]); c = 1]) == 0
    contains(lower(input.resources[_].properties.binding[_].role), "roles/editor")
}

gc_issue["iam_primitive_roles_in_use"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_policy"
	count([c | contains(input.resources[_].properties.binding[_].members[_] , list_var[_]); c = 1]) == 0
    contains(lower(input.resources[_].properties.binding[_].role), "roles/owner")
}

gc_issue["iam_primitive_roles_in_use"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_policy"
	count([c | contains(input.resources[_].properties.binding[_].member[_] , list_var[_]); c = 1]) == 0
    contains(lower(input.resources[_].properties.binding[_].role), "roles/editor")
}

gc_issue["iam_primitive_roles_in_use"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_policy"
	count([c | contains(input.resources[_].properties.binding[_].member[_] , list_var[_]); c = 1]) == 0
    contains(lower(input.resources[_].properties.binding[_].role), "roles/owner")
}

gc_issue["iam_primitive_roles_in_use"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_binding"
	count([c | contains(input.resources[_].properties.members[_] , list_var[_]); c = 1]) == 0
    contains(lower(input.resources[_].properties.role), "roles/editor")
}

gc_issue["iam_primitive_roles_in_use"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_binding"
	count([c | contains(input.resources[_].properties.members[_] , list_var[_]); c = 1]) == 0
    contains(lower(input.resources[_].properties.role), "roles/owner")
}

gc_issue["iam_primitive_roles_in_use"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_binding"
	count([c | contains(input.resources[_].properties.member[_] , list_var[_]); c = 1]) == 0
    contains(lower(input.resources[_].properties.role), "roles/editor")
}

gc_issue["iam_primitive_roles_in_use"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_binding"
	count([c | contains(input.resources[_].properties.member[_] , list_var[_]); c = 1]) == 0
    contains(lower(input.resources[_].properties.role), "roles/owner")
}

gc_issue["iam_primitive_roles_in_use"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_member"
	count([c | contains(input.resources[_].properties.members , list_var[_]); c = 1]) == 0
    contains(lower(input.resources[_].properties.role), "roles/owner")
}

gc_issue["iam_primitive_roles_in_use"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_member"
	count([c | contains(input.resources[_].properties.members , list_var[_]); c = 1]) == 0
    contains(lower(input.resources[_].properties.role), "roles/editor")
}

gc_issue["iam_primitive_roles_in_use"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_member"
	count([c | contains(input.resources[_].properties.member , list_var[_]); c = 1]) == 0
    contains(lower(input.resources[_].properties.role), "roles/owner")
}

gc_issue["iam_primitive_roles_in_use"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_member"
	count([c | contains(input.resources[_].properties.member , list_var[_]); c = 1]) == 0
    contains(lower(input.resources[_].properties.role), "roles/editor")
}

iam_primitive_roles_in_use {
    lower(input.resources[_].type) == google_project_iam[_]
    not gc_issue["iam_primitive_roles_in_use"]
}

iam_primitive_roles_in_use = false {
    gc_issue["iam_primitive_roles_in_use"]
}

iam_primitive_roles_in_use_err = "Ensure, GCP IAM primitive roles are in use." {
    gc_issue["iam_primitive_roles_in_use"]
}

iam_primitive_roles_in_use_metadata := {
    "Policy Code": "PR-GCP-TRF-SAK-007",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure, GCP IAM primitive roles are in use.",
    "Policy Description": "Ensure, GCP IAM users assigned with primitive roles. Primitive roles are Roles that existed prior to Cloud IAM. Primitive roles (owner, editor) are built-in and provide a broader access to resources making them prone to attacks and privilege escalation. Predefined roles provide more granular controls than primitive roles and therefore Predefined roles should be used. Note: For a new GCP project, service accounts are assigned with role/editor permissions. GCP recommends not to revoke the permissions on the SA account. Reference: https://cloud.google.com/iam/docs/service-accounts Limitation: This policy alerts for Service agents which are Google-managed service accounts. Service Agents are by default assigned with some roles by Google cloud and these roles shouldn't be revoked. Reference: https://cloud.google.com/iam/docs/service-agents In case any specific service agent needs to be bypassed, this policy can be cloned and modified accordingly.",
    "Resource Type": ["google_project_iam_policy", "google_project_iam_binding", "google_project_iam_member"],
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects"
}


#
# PR-GCP-TRF-SAK-008
#

default audit_not_config_proper = null

gc_issue["audit_not_config_proper"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_audit_config"
    audit := resource.properties.audit_log_config[_]
    not contains(lower(audit.service), "allservices")
}

gc_issue["audit_not_config_proper"] {
    resource := input.resources[_]
    lower(resource.type) == "google_project_iam_audit_config"
    audit := resource.properties.audit_log_config[_]
	has_property(audit, "exempted_members")
	count(audit.exempted_members[_]) != 0
}

audit_not_config_proper {
    lower(input.resources[_].type) == "google_project_iam_audit_config"
    not gc_issue["audit_not_config_proper"]
}

audit_not_config_proper = false {
    gc_issue["audit_not_config_proper"]
}

audit_not_config_proper_err = "Ensure, GCP Project audit logging is not configured properly across all services and all users in a project." {
    gc_issue["audit_not_config_proper"]
}

audit_not_config_proper_metadata := {
    "Policy Code": "PR-GCP-TRF-SAK-008",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure, GCP Project audit logging is not configured properly across all services and all users in a project.",
    "Policy Description": "Ensure, GCP projects in which cloud audit logging is not configured properly across all services and all users. It is recommended that cloud audit logging is configured to track all Admin activities and read, write access to user data. Logs should be captured for all users and there should be no exempted users in any of the audit config section.",
    "Resource Type": "google_project_iam_audit_config",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects"
}


#
# PR-GCP-TRF-SAK-011
#

default api_target_not_exist = true

api_target_not_exist = false{
    resource := input.resources[_]
    lower(resource.type) == "google_apikeys_key"
    count([c | has_property(resource.properties.restrictions[_], "api_targets"); c=1]) == 0
}

api_target_not_exist_err = "Ensure, GCP API key not restricting any specific API." {
    not api_target_not_exist
}

api_target_not_exist_metadata := {
    "Policy Code": "PR-GCP-TRF-SAK-011",
    "Type": "Iac",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure, GCP API key not restricting any specific API.",
    "Policy Description": "This policy checks GCP API keys that are not restricting any specific APIs. API keys are insecure because they can be viewed publicly, such as from within a browser, or they can be accessed on a device where the key resides. It is recommended to restrict API keys to use (call) only APIs required by an application.",
    "Resource Type": "google_apikeys_key",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys"
}


#
# PR-GCP-TRF-SAK-012
#

default api_key_has_no_specific_restriction = null

gc_attribute_absence["api_key_has_no_specific_restriction"] {
    resource := input.resources[_]
    lower(resource.type) == "google_apikeys_key"
    count([c | has_property(resource.properties.restrictions[_], "browser_key_restrictions"); c=1]) == 0
    count([c | has_property(resource.properties.restrictions[_], "server_key_restrictions"); c=1]) == 0
    count([c | has_property(resource.properties.restrictions[_], "android_key_restrictions"); c=1]) == 0
    count([c | has_property(resource.properties.restrictions[_], "ios_key_restrictions"); c=1]) == 0
}

gc_issue["api_key_has_no_specific_restriction"]{
    resource := input.resources[_]
    lower(resource.type) == "google_apikeys_key"
    has_property(resource.properties.restrictions[_], "browser_key_restrictions")
    browser_key_restriction := resource.properties.restrictions[_].browser_key_restrictions[_]
    contains(browser_key_restriction.allowed_referrers[_], "*")
}   

gc_issue["api_key_has_no_specific_restriction"]{
    resource := input.resources[_]
    lower(resource.type) == "google_apikeys_key"
    has_property(resource.properties.restrictions[_], "browser_key_restrictions")
    browser_key_restriction := resource.properties.restrictions[_].browser_key_restrictions[_]
    contains(lower(browser_key_restriction.allowed_referrers[_]), "*.[tld]")
}

gc_issue["api_key_has_no_specific_restriction"]{
    resource := input.resources[_]
    lower(resource.type) == "google_apikeys_key"
    has_property(resource.properties.restrictions[_], "browser_key_restrictions")
    browser_key_restriction := resource.properties.restrictions[_].browser_key_restrictions[_]
    contains(lower(browser_key_restriction.allowed_referrers[_]), "*.[tld]/*")
}   

gc_issue["api_key_has_no_specific_restriction"]{
    resource := input.resources[_]
    lower(resource.type) == "google_apikeys_key"
    has_property(resource.properties.restrictions[_], "server_key_restrictions")
    server_key_restriction := resource.properties.restrictions[_].server_key_restrictions[_]
    contains(server_key_restriction.allowed_ips[_], "0.0.0.0")
} 

gc_issue["api_key_has_no_specific_restriction"]{
    resource := input.resources[_]
    lower(resource.type) == "google_apikeys_key"
    has_property(resource.properties.restrictions[_], "server_key_restrictions")
    server_key_restriction := resource.properties.restrictions[_].server_key_restrictions[_]
    contains(server_key_restriction.allowed_ips[_], "0.0.0.0/0")
} 

gc_issue["api_key_has_no_specific_restriction"]{
    resource := input.resources[_]
    lower(resource.type) == "google_apikeys_key"
    has_property(resource.properties.restrictions[_], "server_key_restrictions")
    server_key_restriction := resource.properties.restrictions[_].server_key_restrictions[_]
    contains(server_key_restriction.allowed_ips[_], "::/0")
} 

gc_issue["api_key_has_no_specific_restriction"]{
    resource := input.resources[_]
    lower(resource.type) == "google_apikeys_key"
    has_property(resource.properties.restrictions[_], "server_key_restrictions")
    server_key_restriction := resource.properties.restrictions[_].server_key_restrictions[_]
    contains(server_key_restriction.allowed_ips[_], "::0")
} 

api_key_has_no_specific_restriction {
    resource := input.resources[_]
    lower(resource.type) == "google_apikeys_key"
    not gc_issue["api_key_has_no_specific_restriction"]
    not gc_attribute_absence["api_key_has_no_specific_restriction"]
}

api_key_has_no_specific_restriction = false {
    gc_issue["api_key_has_no_specific_restriction"]
    
}

api_key_has_no_specific_restriction = false {
    gc_attribute_absence["api_key_has_no_specific_restriction"]
    
}

api_key_has_no_specific_restriction_err = "Ensure, GCP API key not restricted to use by specified Hosts and Apps." {
    gc_issue["api_key_has_no_specific_restriction"]
    gc_attribute_absence["api_key_has_no_specific_restriction"]
}

api_key_has_no_specific_restriction_metadata := {
    "Policy Code": "PR-GCP-TRF-SAK-012",
    "Type": "Iac",
    "Product": "GCP",
    "Language": "Terraform",
    "Policy Title": "Ensure, GCP API key not restricted to use by specified Hosts and Apps.",
    "Policy Description": "This policy checks GCP API key not restricted to use by specified Hosts and Apps. Unrestricted keys are insecure because they can be viewed publicly, such as from within a browser, or they can be accessed on a device where the key resides. It is recommended to restrict API key usage to trusted hosts, HTTP referrers and apps.",
    "Resource Type": "google_apikeys_key",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys"
}