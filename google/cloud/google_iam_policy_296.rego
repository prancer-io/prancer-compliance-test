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