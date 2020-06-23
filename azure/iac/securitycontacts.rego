package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.security/securitycontacts

#
# Security contact emails is not set in Security Center (296)
#

default securitycontacts = null

securitycontacts {
    lower(input.type) == "microsoft.security/securitycontacts"
    re_match("^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$", input.properties.email)
}

securitycontacts = false {
    lower(input.type) == "microsoft.security/securitycontacts"
    re_match("^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$", input.properties.email) == false
}

securitycontacts = false {
    lower(input.type) == "microsoft.security/securitycontacts"
    count([c | input.properties.email; c := 1]) == 0
}

securitycontacts_err = "Security contact emails is not set in Security Center" {
    securitycontacts == false
}
