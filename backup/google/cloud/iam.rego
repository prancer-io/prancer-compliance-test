package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }

array_element_contains(target_array, element_string) = true {
  contains(lower(target_array[_]), lower(element_string))
} else = false { true }

array_element_in(target_array, in_array) = true {
  lower(target_array[_]) == lower(in_array[_])
} else = false { true }

array_element_contains_in(target_array, in_array) = true {
  contains(lower(target_array[_]), lower(in_array[_]))
} else = false { true }

# https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts.keys

#
# PR-GCP-CLD-IAM-001
#

default svc_user_managed_key_rotated_every_90_days = null

gcp_issue["svc_user_managed_key_rotated_every_90_days"] {
    #svcKey := input.GOOGLE_SERVICE_AC_KEY[_]
    lower(input.keyType) == "user_managed"
    time.now_ns() - time.parse_rfc3339_ns(input.validAfterTime) > 7776000000000000
}

svc_user_managed_key_rotated_every_90_days {
    # lower(input.resources[i].type) == "iam.v1.serviceaccounts.key"
    not gcp_issue["svc_user_managed_key_rotated_every_90_days"]
}

svc_user_managed_key_rotated_every_90_days = false {
    gcp_issue["svc_user_managed_key_rotated_every_90_days"]
}

svc_user_managed_key_rotated_every_90_days_err = "User managed service account keys currently not getting rotated every 90 days" {
    gcp_issue["svc_user_managed_key_rotated_every_90_days"]
}

svc_user_managed_key_rotated_every_90_days_metadata := {
    "Policy Code": "PR-GCP-CLD-IAM-001",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "User managed service account keys should be rotated every 90 days",
    "Policy Description": "This policy identifies user-managed service account keys which are not rotated from last 90 days or more. Rotating Service Account keys will reduce the window of opportunity for an access key that is associated with a compromised or terminated account to be used. Service Account keys should be rotated to ensure that data cannot be accessed with an old key which might have been lost, cracked, or stolen. It is recommended that all user-managed service account keys are regularly rotated.",
    "Resource Type": "iam.v1.serviceaccounts.key",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts.keys"
}


#
# PR-GCP-CLD-IAM-002
# 

default gcp_dont_have_non_corporate_account = null

gcp_issue["gcp_dont_have_non_corporate_account"] {
    bindings := input.bindings[_]
    array_element_contains(bindings.members, "gmail.com")
}

gcp_dont_have_non_corporate_account {
    not gcp_issue["gcp_dont_have_non_corporate_account"]
}

gcp_dont_have_non_corporate_account = false {
    gcp_issue["gcp_dont_have_non_corporate_account"]
}

gcp_dont_have_non_corporate_account_err = "Non-corporate accounts currently have access to Google Cloud Platform (GCP) resources." {
    gcp_issue["gcp_dont_have_non_corporate_account"]
}

gcp_dont_have_non_corporate_account_metadata := {
    "Policy Code": "PR-GCP-CLD-IAM-002",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure, Non-corporate accounts don't have access to Google Cloud Platform (GCP) resources",
    "Policy Description": "Organizations does not have any control over personal Gmail accounts. Thus, it is recommended that you use fully managed corporate Google accounts for increased visibility, auditing, and control over access to Cloud Platform resources.",
    "Resource Type": "projects.getIamPolicy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects/getIamPolicy"
}


#
# PR-GCP-CLD-IAM-003
# depends on https://github.com/prancer-io/prancer-compliance-test/issues/564

default service_account_dont_have_admin_privileges = null

gcp_issue["service_account_dont_have_admin_privileges"] {
    bindings := input.bindings[_]
    count([c | startswith(lower(bindings.members[_]), "serviceaccount:"); c := 1]) > 0
    lower(bindings.role) == "admin"
}

gcp_issue["service_account_dont_have_admin_privileges"] {
    bindings := input.bindings[_]
    count([c | startswith(lower(bindings.members[_]), "serviceaccount:"); c := 1]) > 0
    lower(bindings.role) == "roles/editor"
}

gcp_issue["service_account_dont_have_admin_privileges"] {
    bindings := input.bindings[_]
    count([c | startswith(lower(bindings.members[_]), "serviceaccount:"); c := 1]) > 0
    lower(bindings.role) == "roles/owner"   
}

service_account_dont_have_admin_privileges {
    count([c | input.bindings[_]; c := 1]) > 0
    not gcp_issue["service_account_dont_have_admin_privileges"]
}

service_account_dont_have_admin_privileges = false {
    count([c | input.bindings[_]; c := 1]) > 0
    gcp_issue["service_account_dont_have_admin_privileges"]
}

service_account_dont_have_admin_privileges_err = "Service accounts currently have admin privileges" {
    count([c | input.bindings[_]; c := 1]) > 0
    gcp_issue["service_account_dont_have_admin_privileges"]
}

service_account_dont_have_admin_privileges_metadata := {
    "Policy Code": "PR-GCP-CLD-IAM-003",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Service accounts should not have admin privileges",
    "Policy Description": "A ServiceAccount Access holder can perform critical actions like delete, update change settings, etc. without user intervention. For this reason, it's recommended that service accounts not have Admin rights.",
    "Resource Type": "projects.getIamPolicy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects/getIamPolicy"
}


#
# PR-GCP-CLD-IAM-004
# can be more simplified if we can enhance as per https://github.com/prancer-io/cloud-validation-framework/issues/705

default seperation_of_duties_been_enforced_on_user_accounts = null

gcp_issue["seperation_of_duties_been_enforced_on_user_accounts"] {
    binding := input.bindings[_]
    member := binding.members[_]
    startswith(lower(member), "user:")
    
    bindingToCompareForServiceAccountAdmin := input.bindings[_]
    count([c | bindingToCompareForServiceAccountAdmin.members[_] == member ; c := 1]) > 0
    startswith(lower(bindingToCompareForServiceAccountAdmin.role), "roles/iam.serviceaccountadmin")
    
    bindingToCompareForServiceAccountTokenCreator := input.bindings[_]
    count([c | bindingToCompareForServiceAccountTokenCreator.members[_] == member ; c := 1]) > 0
    startswith(lower(bindingToCompareForServiceAccountTokenCreator.role), "roles/iam.serviceaccounttokencreator")
}

gcp_issue["seperation_of_duties_been_enforced_on_user_accounts"] {
    binding := input.bindings[_]
    member := binding.members[_]
    startswith(lower(member), "user:")
    
    bindingToCompareForServiceAccountAdmin := input.bindings[_]
    count([c | bindingToCompareForServiceAccountAdmin.members[_] == member ; c := 1]) > 0
    startswith(lower(bindingToCompareForServiceAccountAdmin.role), "roles/iam.serviceaccountadmin")
    
    bindingToCompareForServiceAccountUser := input.bindings[_]
    count([c | bindingToCompareForServiceAccountUser.members[_] == member ; c := 1]) > 0
    startswith(lower(bindingToCompareForServiceAccountUser.role), "roles/iam.serviceaccountuser")
}

gcp_issue["seperation_of_duties_been_enforced_on_user_accounts"] {
    binding := input.bindings[_]
    member := binding.members[_]
    startswith(lower(member), "user:")
    
    bindingToCompareForServiceAccountAdmin := input.bindings[_]
    count([c | bindingToCompareForServiceAccountAdmin.members[_] == member ; c := 1]) > 0
    startswith(lower(bindingToCompareForServiceAccountAdmin.role), "roles/iam.serviceaccountadmin")
    
    bindingToCompareForWorkloadIdentityUser := input.bindings[_]
    count([c | bindingToCompareForWorkloadIdentityUser.members[_] == member ; c := 1]) > 0
    startswith(lower(bindingToCompareForWorkloadIdentityUser.role), "roles/iam.workloadidentityuser")
}

seperation_of_duties_been_enforced_on_user_accounts {
    count([c | input.bindings[_]; c := 1]) > 0
    not gcp_issue["seperation_of_duties_been_enforced_on_user_accounts"]
}

seperation_of_duties_been_enforced_on_user_accounts = false {
    count([c | input.bindings[_]; c := 1]) > 0
    gcp_issue["seperation_of_duties_been_enforced_on_user_accounts"]
}

seperation_of_duties_been_enforced_on_user_accounts_err = "Separation of duties currently not enforced on user account containg service account related roles" {
    count([c | input.bindings[_]; c := 1]) > 0
    gcp_issue["seperation_of_duties_been_enforced_on_user_accounts"]
}

seperation_of_duties_been_enforced_on_user_accounts_metadata := {
    "Policy Code": "PR-GCP-CLD-IAM-004",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Separation of duties should be enforced on user accounts containing service account related roles",
    "Policy Description": "Separation of duties means that an individual should not have enough permissions that will enable him to complete a malicious action. Users should not have both the abilities to create and to use a service account. This might lead them to access resources that they should not have in the first place.",
    "Resource Type": "projects.getIamPolicy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects/getIamPolicy"
}


#
# PR-GCP-CLD-IAM-005
# 

default seperation_of_duties_been_enforced_on_user_accounts_for_kms_privileges = null

gcp_issue["seperation_of_duties_been_enforced_on_user_accounts_for_kms_privileges"] {
    binding := input.bindings[_]
    member := binding.members[_]
    startswith(lower(member), "user:")
    
    bindingToCompareForCloudKMSAdmin := input.bindings[_]
    count([c | bindingToCompareForCloudKMSAdmin.members[_] == member ; c := 1]) > 0
    startswith(lower(bindingToCompareForCloudKMSAdmin.role), "'roles/cloudkms.admin")
    
    bindingToCompareForCloudKMSCryptoKeyEncrypterDecrypter := input.bindings[_]
    count([c | bindingToCompareForCloudKMSCryptoKeyEncrypterDecrypter.members[_] == member ; c := 1]) > 0
    startswith(lower(bindingToCompareForCloudKMSCryptoKeyEncrypterDecrypter.role), "roles/cloudkms.cryptokeyencrypterdecrypter")
}

gcp_issue["seperation_of_duties_been_enforced_on_user_accounts_for_kms_privileges"] {
    binding := input.bindings[_]
    member := binding.members[_]
    startswith(lower(member), "user:")
    
    bindingToCompareForCloudKMSAdmin := input.bindings[_]
    count([c | bindingToCompareForCloudKMSAdmin.members[_] == member ; c := 1]) > 0
    startswith(lower(bindingToCompareForCloudKMSAdmin.role), "'roles/cloudkms.admin")
    
    bindingToCompareForCloudKMSCryptoKeyEncrypter := input.bindings[_]
    count([c | bindingToCompareForCloudKMSCryptoKeyEncrypter.members[_] == member ; c := 1]) > 0
    startswith(lower(bindingToCompareForCloudKMSCryptoKeyEncrypter.role), "roles/cloudkms.cryptokeyencrypter")
}

gcp_issue["seperation_of_duties_been_enforced_on_user_accounts_for_kms_privileges"] {
    binding := input.bindings[_]
    member := binding.members[_]
    startswith(lower(member), "user:")
    
    bindingToCompareForCloudKMSAdmin := input.bindings[_]
    count([c | bindingToCompareForCloudKMSAdmin.members[_] == member ; c := 1]) > 0
    startswith(lower(bindingToCompareForCloudKMSAdmin.role), "'roles/cloudkms.admin")
    
    bindingToCompareForCloudKMSCryptoKeyDecrypter := input.bindings[_]
    count([c | bindingToCompareForCloudKMSCryptoKeyDecrypter.members[_] == member ; c := 1]) > 0
    startswith(lower(bindingToCompareForCloudKMSCryptoKeyDecrypter.role), "roles/cloudkms.cryptokeydecrypter")
}

seperation_of_duties_been_enforced_on_user_accounts_for_kms_privileges {
    count([c | input.bindings[_]; c := 1]) > 0
    not gcp_issue["seperation_of_duties_been_enforced_on_user_accounts_for_kms_privileges"]
}

seperation_of_duties_been_enforced_on_user_accounts_for_kms_privileges = false {
    count([c | input.bindings[_]; c := 1]) > 0
    gcp_issue["seperation_of_duties_been_enforced_on_user_accounts_for_kms_privileges"]
}

seperation_of_duties_been_enforced_on_user_accounts_for_kms_privileges_err = "Separation of duties currently not enforced on user accounts containg KMS related roles" {
    count([c | input.bindings[_]; c := 1]) > 0
    gcp_issue["seperation_of_duties_been_enforced_on_user_accounts_for_kms_privileges"]
}

seperation_of_duties_been_enforced_on_user_accounts_for_kms_privileges_metadata := {
    "Policy Code": "PR-GCP-CLD-IAM-005",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Separation of duties should be enforced on user accounts containing KMS related roles",
    "Policy Description": "It is recommended that the principle of 'Separation of Duties' is enforced while assigning KMS related roles to users.The built-in/predefined IAM role Cloud KMS Admin allows the user/identity to create, delete, and manage service account(s). The built-in/predefined IAM role Cloud KMS CryptoKey Encrypter/Decrypter allows the user/identity (with adequate privileges on concerned resources) to encrypt and decrypt data at rest using an encryption key(s).The built-in/predefined IAM role Cloud KMS CryptoKey Encrypter allows the user/identity (with adequate privileges on concerned resources) to encrypt data at rest using an encryption key(s). The built-in/predefined IAM role Cloud KMS CryptoKey Decrypter allows the user/identity (with adequate privileges on concerned resources) to decrypt data at rest using an encryption key(s). Separation of duties is the concept of ensuring that one individual does not have all necessary permissions to be able to complete a malicious action. In Cloud KMS, this could be an action such as using a key to access and decrypt data a user should not normally have access to. Separation of duties is a business control typically used in larger organizations, meant to help avoid security or privacy incidents and errors. It is considered best practice. No user(s) should have Cloud KMS Admin and any of the Cloud KMS CryptoKey Encrypter/Decrypter, Cloud KMS CryptoKey Encrypter, Cloud KMS CryptoKey Decrypter roles assigned at the same time",
    "Resource Type": "projects.getIamPolicy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects/getIamPolicy"
}


#
# PR-GCP-CLD-IAM-006
# 

default user_account_dont_have_service_account_related_privileges = null

gcp_issue["user_account_dont_have_service_account_related_privileges"] {
    bindings := input.bindings[_]
    count([c | startswith(lower(bindings.members[_]), "user:"); c := 1]) > 0
    lower(bindings.role) == "roles/iam.serviceaccountactor"
}

gcp_issue["user_account_dont_have_service_account_related_privileges"] {
    bindings := input.bindings[_]
    count([c | startswith(lower(bindings.members[_]), "user:"); c := 1]) > 0
    lower(bindings.role) == "roles/iam.serviceaccountuser"
}

gcp_issue["user_account_dont_have_service_account_related_privileges"] {
    bindings := input.bindings[_]
    count([c | startswith(lower(bindings.members[_]), "user:"); c := 1]) > 0
    lower(bindings.role) == "roles/iam.serviceaccounttokencreator"
}

user_account_dont_have_service_account_related_privileges {
    count([c | input.bindings[_]; c := 1]) > 0
    not gcp_issue["user_account_dont_have_service_account_related_privileges"]
}

user_account_dont_have_service_account_related_privileges = false {
    count([c | input.bindings[_]; c := 1]) > 0
    gcp_issue["user_account_dont_have_service_account_related_privileges"]
}

user_account_dont_have_service_account_related_privileges_err = "User account currently have Service Account User or Service Account Token Creator roles at project level" {
    count([c | input.bindings[_]; c := 1]) > 0
    gcp_issue["user_account_dont_have_service_account_related_privileges"]
}

user_account_dont_have_service_account_related_privileges_metadata := {
    "Policy Code": "PR-GCP-CLD-IAM-006",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "User account should not have Service Account User or Service Account Token Creator roles at project level",
    "Policy Description": "It is recommended to assign the Service Account User (iam.serviceAccountUser) and Service Account Token Creator (iam.serviceAccountTokenCreator) roles to a user for a specific service account rather than assigning the role to a user at project level.",
    "Resource Type": "projects.getIamPolicy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects/getIamPolicy"
}


#
# PR-GCP-CLD-IAM-007
# 

#list_var = ["appspot.gserviceaccount.com",
#            "developer.gserviceaccount.com",
#            "cloudservices.gserviceaccount.com",
#            "system.gserviceaccount.com",
#            "cloudbuild.gserviceaccount.com"]

default iam_primitive_roles_are_not_in_use = null

gcp_issue["iam_primitive_roles_are_not_in_use"] {
	#count([c | contains(input.bindings[_].members[_] , list_var[_]); c = 1]) == 0
    lower(input.bindings[_].role) == "roles/editor"
}

gcp_issue["iam_primitive_roles_are_not_in_use"] {
	#count([c | contains(input.bindings[_].members[_] , list_var[_]); c = 1]) == 0
    lower(input.bindings[_].role) == "roles/owner"
}

iam_primitive_roles_are_not_in_use {
    not gcp_issue["iam_primitive_roles_are_not_in_use"]
}

iam_primitive_roles_are_not_in_use = false {
    gcp_issue["iam_primitive_roles_are_not_in_use"]
}

iam_primitive_roles_are_not_in_use_err = "IAM primitive roles currently in use. Avoid using those roles if not necessary." {
    gcp_issue["iam_primitive_roles_are_not_in_use"]
}

iam_primitive_roles_are_not_in_use_metadata := {
    "Policy Code": "PR-GCP-CLD-IAM-007",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Avoid using IAM primitive roles",
    "Policy Description": "Basic/Primitive roles include many permissions across all GCP services. Using them will result violation of the principle of least privilege. You should avoid using basic roles, and use predefined roles or custom roles instead.",
    "Resource Type": "projects.getIamPolicy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects/getIamPolicy"
}


#
# PR-GCP-CLD-IAM-008
# 

default project_has_audit_logging_configured_for_all_services_and_users = null

gcp_issue["project_has_audit_logging_configured_for_all_services_and_users"] {
    count([c | lower(input.auditConfigs[_].service) == "allservices"; c := 1]) == 0
}

gcp_issue["project_has_audit_logging_configured_for_all_services_and_users"] {
    auditConfigs := input.auditConfigs[_]
    lower(auditConfigs.service) == "allservices"
    auditLogConfigs := auditConfigs.auditLogConfigs[_]
	has_property(auditLogConfigs, "exemptedMembers")
	count(auditLogConfigs.exemptedMembers) > 0
}

project_has_audit_logging_configured_for_all_services_and_users {
    not gcp_issue["project_has_audit_logging_configured_for_all_services_and_users"]
}

project_has_audit_logging_configured_for_all_services_and_users = false {
    gcp_issue["project_has_audit_logging_configured_for_all_services_and_users"]
}

project_has_audit_logging_configured_for_all_services_and_users_err = "Audit logging is currently not configured for all services and users in gcp project" {
    gcp_issue["project_has_audit_logging_configured_for_all_services_and_users"]
}

project_has_audit_logging_configured_for_all_services_and_users_metadata := {
    "Policy Code": "PR-GCP-CLD-IAM-008",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure audit logging is configured for all services and users in a project",
    "Policy Description": "This policy will audit GCP projects which dont have audit logging configured for all services and users. It's recommended that cloud audit logging is configured to track all Admin activities and read, write access to user data. Logs should be captured for all users and there should be no exempted users in any of the audit config section.",
    "Resource Type": "projects.getIamPolicy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects/getIamPolicy"
}


#
# PR-GCP-CLD-IAM-009
#

default svc_dont_have_user_managed_key = null

gcp_issue["svc_dont_have_user_managed_key"] {
    svcKey := input.GOOGLE_SERVICE_AC_KEY[_]
    svc := input.GOOGLE_SERVICE_AC[_]
    lower(svcKey.keyType) == "user_managed"
    startswith(lower(svcKey.name), lower(svc.name))
}

svc_dont_have_user_managed_key = false {
    gcp_issue["svc_dont_have_user_managed_key"]
}

svc_dont_have_user_managed_key {
    not gcp_issue["svc_dont_have_user_managed_key"]
}

svc_dont_have_user_managed_key_err = "Service account currently have user managed key" {
    gcp_issue["svc_dont_have_user_managed_key"]
}

svc_dont_have_user_managed_key_metadata := {
    "Policy Code": "PR-GCP-CLD-IAM-009",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Service account should not have user managed keys",
    "Policy Description": "This policy audit service accounts that usage user managed keys instead of Google-managed. For user-managed keys, the User has to take ownership of key management activities. Even after owner precaution, keys can be easily leaked by common development malpractices like checking keys into the source code or leaving them in downloads directory or accidentally leaving them on support blogs/channels. So It is recommended to limit the use of User-managed service account keys and instead use Google-managed keys which can not be downloaded.",
    "Resource Type": "iam.v1.serviceaccounts.key",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts.keys"
}


#
# PR-GCP-CLD-IAM-010
#

default api_key_rotated_every_90_days = null

gcp_issue["api_key_rotated_every_90_days"] {
    time.now_ns() - time.parse_rfc3339_ns(input.createTime) > 7776000000000000
}

api_key_rotated_every_90_days {
    not gcp_issue["api_key_rotated_every_90_days"]
}

api_key_rotated_every_90_days = false {
    gcp_issue["api_key_rotated_every_90_days"]
}

api_key_rotated_every_90_days_err = "API key currently not rotating in every 90 days." {
    gcp_issue["api_key_rotated_every_90_days"]
}

api_key_rotated_every_90_days_metadata := {
    "Policy Code": "PR-GCP-CLD-IAM-010",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure API keys are rotated every 90 days",
    "Policy Description": "This policy identifies GCP API keys for which the creation date is aged more than 90 days. Google recommends using the standard authentication flow instead of API Keys. However, there are limited cases where API keys are more appropriate. API keys should be rotated to ensure that data cannot be accessed with an old key that might have been lost, cracked, or stolen.",
    "Resource Type": "projects.locations.keys",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys"
}


#
# PR-GCP-CLD-IAM-011
#

default project_has_no_unrestricted_api_keys_created = null

project_has_no_unrestricted_api_keys_created = false {
    not has_property(input, "restrictions")
}

project_has_no_unrestricted_api_keys_created {
    has_property(input, "restrictions")
}

project_has_no_unrestricted_api_keys_created_err = "Project currently have unrestricted API keys created. Make sure to restrict them all for specific Application and APIs." {
    not project_has_no_unrestricted_api_keys_created
}

project_has_no_unrestricted_api_keys_created_metadata := {
    "Policy Code": "PR-GCP-CLD-IAM-011",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Project should not have unrestricted API keys created",
    "Policy Description": "API keys are unrestricted by default. Unrestricted keys are insecure because they can be used by anyone from anywhere. For production applications, you should set both application restrictions and API restrictions.",
    "Resource Type": "projects.locations.keys",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys"
}


#
# PR-GCP-CLD-IAM-012
#

default api_key_has_application_restriction = null

gcp_attribute_absence["api_key_has_application_restriction"] {   
    not has_property(input.restrictions, "browserKeyRestrictions")
    not has_property(input.restrictions, "serverKeyRestrictions")
    not has_property(input.restrictions, "androidKeyRestrictions")
    not has_property(input.restrictions, "iosKeyRestrictions")
}

gcp_issue["api_key_has_application_restriction"] {
    has_property(input.restrictions, "browserKeyRestrictions")
    browser_key_restriction := input.restrictions.browserKeyRestrictions[_]
    array_element_contains(browser_key_restriction.allowedReferrers, "*")
}   

gcp_issue["api_key_has_application_restriction"] {
    has_property(input.restrictions, "browserKeyRestrictions")
    browser_key_restriction := input.restrictions.browserKeyRestrictions[_]
    array_element_contains(browser_key_restriction.allowedReferrers, "*.[tld]")
}   

gcp_issue["api_key_has_application_restriction"] {
    has_property(input.restrictions, "browserKeyRestrictions")
    browser_key_restriction := input.restrictions.browserKeyRestrictions[_]
    array_element_contains(browser_key_restriction.allowedReferrers, "*.[tld]/*")
}   

gcp_issue["api_key_has_application_restriction"] {
    has_property(input.restrictions, "serverKeyRestrictions")
    server_key_restriction := input.restrictions.serverKeyRestrictions[_]
    array_element_contains(server_key_restriction.allowedIps, "0.0.0.0")
}   

gcp_issue["api_key_has_application_restriction"] {
    has_property(input.restrictions, "serverKeyRestrictions")
    server_key_restriction := input.restrictions.serverKeyRestrictions[_]
    array_element_contains(server_key_restriction.allowedIps, "0.0.0.0/0")
}   

gcp_issue["api_key_has_application_restriction"] {
    has_property(input.restrictions, "serverKeyRestrictions")
    server_key_restriction := input.restrictions.serverKeyRestrictions[_]
    array_element_contains(server_key_restriction.allowedIps, "::/0")
}   

gcp_issue["api_key_has_application_restriction"] {
    has_property(input.restrictions, "serverKeyRestrictions")
    server_key_restriction := input.restrictions.serverKeyRestrictions[_]
    array_element_contains(server_key_restriction.allowedIps, "::0")
}   

api_key_has_application_restriction = false {
    gcp_attribute_absence["api_key_has_application_restriction"]
}

api_key_has_application_restriction = false {
    gcp_issue["api_key_has_application_restriction"]
}

api_key_has_application_restriction {
    not gcp_attribute_absence["api_key_has_application_restriction"]
    not gcp_issue["api_key_has_application_restriction"]
}

api_key_has_application_restriction_err = "API key currently dont have any application restriction" {
    gcp_issue["api_key_has_application_restriction"]
} else = "API key currently dont have any application restriction" {
    gcp_attribute_absence["api_key_has_application_restriction"]
}

api_key_has_application_restriction_metadata := {
    "Policy Code": "PR-GCP-CLD-IAM-012",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "API key should have application restriction",
    "Policy Description": "Application restrictions limit an API key's usage to specific websites, IP addresses, Android applications, or iOS applications. You can set one application restriction per key. Unrestricted keys are insecure because they can be viewed publicly, such as from within a browser, or they can be accessed on a device where the key resides. It is recommended to restrict API key usage to trusted hosts, HTTP referrers and apps.",
    "Resource Type": "projects.locations.keys",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys"
}


#
# PR-GCP-CLD-IAM-013
#

default project_has_no_api_keys_created = null

project_has_no_api_keys_created = false {
    not input.uid
}

project_has_no_api_keys_created {
    input.uid
}

project_has_no_api_keys_created_err = "Project currently has API keys created. Make sure to remove all and use standard authentication flow instead." {
    not project_has_no_api_keys_created
}

project_has_no_api_keys_created_metadata := {
    "Policy Code": "PR-GCP-CLD-IAM-013",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure API keys are not created for project",
    "Policy Description": "This policy identifies GCP projects where API keys are created. Keys are insecure because they can be viewed publicly, such as from within a browser, or they can be accessed on a device where the key resides. To avoid the security risk in using API keys, it is recommended to use standard authentication flow instead.\n\nNote: There are limited cases where API keys are more appropriate. For example, if there is a mobile application that needs to use the Google Cloud Translation API, but doesn't otherwise need a backend server, API keys are the simplest way to authenticate to that API. If a business requires API keys to be used, then the API keys should be secured using appropriate IAM policies.",
    "Resource Type": "projects.locations.keys",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys"
}


#
# PR-GCP-CLD-IAM-014
# 
default mfa_enabled_for_identity_platform_accounts = null

gcp_attribute_absence["mfa_enabled_for_identity_platform_accounts"]{
    not input.users
}

gcp_attribute_absence["mfa_enabled_for_identity_platform_accounts"] {
    users := input.users[_]
    not users.mfaInfo
}

mfa_enabled_for_identity_platform_accounts {
    not gcp_attribute_absence["mfa_enabled_for_identity_platform_accounts"]
}

mfa_enabled_for_identity_platform_accounts = false {
    gcp_attribute_absence["mfa_enabled_for_identity_platform_accounts"]
}

mfa_enabled_for_identity_platform_accounts_err = "All identity platform accounts currently dont have MFA enabled" {
    gcp_attribute_absence["mfa_enabled_for_identity_platform_accounts"]
}

mfa_enabled_for_identity_platform_accounts_metadata := {
    "Policy Code": "PR-GCP-CLD-IAM-014",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "MFA should be enabled for all Identity Platform accounts",
    "Policy Description": "This policy identity and audit GCP Identity platform accounts which dont have MFA enabled.",
    "Resource Type": "projects.accounts.batchGet",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/identity-platform/docs/reference/rest/v1/projects.accounts/batchGet"
}


#
# PR-GCP-CLD-IAM-015
# 

default service_account_dont_have_permission_to_use_other_service_accounts_or_set_iam_policy = null

gcp_issue["service_account_dont_have_permission_to_use_other_service_accounts_or_set_iam_policy"] {
    bindings := input.bindings[_]
    count([c | startswith(lower(bindings.members[_]), "serviceaccount:"); c := 1]) > 0
    # need to reverify this role
    startswith(lower(bindings.role), "roles/iam.serviceaccount")
}

gcp_issue["service_account_dont_have_permission_to_use_other_service_accounts_or_set_iam_policy"] {
    bindings := input.bindings[_]
    count([c | startswith(lower(bindings.members[_]), "serviceaccount:"); c := 1]) > 0
    startswith(lower(bindings.role), "roles/iam.securityadmin")
}

service_account_dont_have_permission_to_use_other_service_accounts_or_set_iam_policy {
    count([c | input.bindings[_]; c := 1]) > 0
    not gcp_issue["service_account_dont_have_permission_to_use_other_service_accounts_or_set_iam_policy"]
}

service_account_dont_have_permission_to_use_other_service_accounts_or_set_iam_policy = false {
    count([c | input.bindings[_]; c := 1]) > 0
    gcp_issue["service_account_dont_have_permission_to_use_other_service_accounts_or_set_iam_policy"]
}

service_account_dont_have_permission_to_use_other_service_accounts_or_set_iam_policy_err = "Service accounts currently have admin privileges." {
    count([c | input.bindings[_]; c := 1]) > 0
    gcp_issue["service_account_dont_have_permission_to_use_other_service_accounts_or_set_iam_policy"]
}

service_account_dont_have_permission_to_use_other_service_accounts_or_set_iam_policy_metadata := {
    "Policy Code": "PR-GCP-CLD-IAM-015",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Service accounts should not have permissions to use other service accounts or set iam policies",
    "Policy Description": "In case of a compromised service account, an attacker would be able to make lateral movement easily. Therefore you should avoid giving a service account permissions to use other service accounts or to set iam policies.",
    "Resource Type": "projects.getIamPolicy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects/getIamPolicy"
}


#
# PR-GCP-CLD-IAM-016
# 

default permission_not_granted_to_impersonate_service_account_at_project_level = null

gcp_issue["permission_not_granted_to_impersonate_service_account_at_project_level"] {
    bindings := input.bindings[_]
    startswith(lower(bindings.role), "roles/iam.workloadidentityuser")
}

gcp_issue["permission_not_granted_to_impersonate_service_account_at_project_level"] {
    bindings := input.bindings[_]
    startswith(lower(bindings.role), "roles/iam.serviceaccountuser")
}

gcp_issue["permission_not_granted_to_impersonate_service_account_at_project_level"] {
    bindings := input.bindings[_]
    startswith(lower(bindings.role), "roles/iam.serviceaccounttokencreator")
}

permission_not_granted_to_impersonate_service_account_at_project_level {
    count([c | input.bindings[_]; c := 1]) > 0
    not gcp_issue["permission_not_granted_to_impersonate_service_account_at_project_level"]
}

permission_not_granted_to_impersonate_service_account_at_project_level = false {
    count([c | input.bindings[_]; c := 1]) > 0
    gcp_issue["permission_not_granted_to_impersonate_service_account_at_project_level"]
}

permission_not_granted_to_impersonate_service_account_at_project_level_err = "Permission to impersonate service account currently granted at project level" {
    count([c | input.bindings[_]; c := 1]) > 0
    gcp_issue["permission_not_granted_to_impersonate_service_account_at_project_level"]
}

permission_not_granted_to_impersonate_service_account_at_project_level_metadata := {
    "Policy Code": "PR-GCP-CLD-IAM-016",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Permission to impersonate service account should not be granted at project level",
    "Policy Description": "Granting users or service accounts with one of the roles: roles/iam.workloadIdentityUser or roles/iam.serviceAccountUser or roles/iam.serviceAccountTokenCreator will in practice grant them with all of the permissions of the service accounts in the project, which violates the principle of least privilege. These roles needs to be granted at the service account level and not project level.",
    "Resource Type": "projects.getIamPolicy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects/getIamPolicy"
}


#
# PR-GCP-CLD-IAM-017
# 

default iam_user_dont_have_permission_to_deploy_all_resources = null

gcp_issue["iam_user_dont_have_permission_to_deploy_all_resources"] {
    bindings := input.bindings[_]
    count([c | startswith(lower(bindings.members[_]), "user:"); c := 1]) > 0
    lower(bindings.role) == "roles/deploymentmanager.editor"
}

iam_user_dont_have_permission_to_deploy_all_resources {
    count([c | input.bindings[_]; c := 1]) > 0
    not gcp_issue["iam_user_dont_have_permission_to_deploy_all_resources"]
}

iam_user_dont_have_permission_to_deploy_all_resources = false {
    count([c | input.bindings[_]; c := 1]) > 0
    gcp_issue["iam_user_dont_have_permission_to_deploy_all_resources"]
}

iam_user_dont_have_permission_to_deploy_all_resources_err = "IAM user currently have permission to deploy all resources. Make sure this permission is only given to admin users" {
    count([c | input.bindings[_]; c := 1]) > 0
    gcp_issue["iam_user_dont_have_permission_to_deploy_all_resources"]
}

iam_user_dont_have_permission_to_deploy_all_resources_metadata := {
    "Policy Code": "PR-GCP-CLD-IAM-017",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "IAM user should not have permission to deploy all resources",
    "Policy Description": "A user with 'roles/deploymentmanager.editor' role and 'deploymentmanager.deployments.create' permission can create almost any resource. Make sure this permission is only given to admin users",
    "Resource Type": "projects.getIamPolicy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/resource-manager/reference/rest/v1/projects/getIamPolicy"
}


#
# PR-GCP-CLD-IAM-018
#

default api_key_has_api_restriction = null

api_key_has_api_restriction = false {
    not has_property(input, "restrictions")
}

api_key_has_api_restriction = false {
    not has_property(input.restrictions, "apiTargets")
}

api_key_has_api_restriction = false {
    count(input.restrictions.apiTargets) <= 0
}

api_key_has_api_restriction {
    count(input.restrictions.apiTargets) > 0
}

api_key_has_api_restriction_err = "Project currently have unrestricted API keys with no API restrictions. Make sure to restrict them all for specific APIs." {
    not api_key_has_api_restriction
}

api_key_has_api_restriction_metadata := {
    "Policy Code": "PR-GCP-CLD-IAM-018",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "API key should have API restriction",
    "Policy Description": "API keys are unrestricted by default. Those are insecure because they can be viewed publicly, such as from within a browser, or they can be accessed on a device where the key resides. It is recommended to restrict API keys to use (call) only APIs required by an application.",
    "Resource Type": "projects.locations.keys",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys"
}
