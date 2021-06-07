#
# PR-GCP-0026
#

package rule
default rulepass = false

# GCP IAM Service account has admin privileges

rulepass = true {
    count(userRole) >= 2
}

# user contains iam.gserviceaccount.com AND
# (roles[*] contains admin or roles[*] contains Admin or roles[*] contains roles/editor or roles[*] contains roles/owner)

userRole["adminUser"] {
    contains(input.bindings[_].role, "admin")
}

userRole["editorUser"] {
    contains(input.bindings[_].role, "roles/editor")
}

userRole["ownerUser"] {
    contains(input.bindings[_].role, "roles/owner")
}

userRole["serviceAccountUser"] {
    contains(input.bindings[_].members[_], "iam.gserviceaccount.com")
}

metadata := {
    "Policy Code": "PR-GCP-0026",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP IAM Service account has admin privileges",
    "Policy Description": "This policy identifies service accounts which have admin privileges. Application uses the service account to make requests to the Google API of a service so that the users aren't directly involved. It is recommended not to use admin access for ServiceAccount.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": ""
}
