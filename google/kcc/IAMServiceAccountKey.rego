package rule

# https://cloud.google.com/config-connector/docs/reference/resource-docs/iam/iamserviceaccountkey

#
# API_KEY_NOT_ROTATED
#

default api_key_not_rotated = null

gc_issue["api_key_not_rotated"] {
    lower(input.kind) == "iamserviceaccountkey"
    time.now_ns() - time.parse_rfc3339_ns(input.spec.validAfter) > 7776000000000000
}

api_key_not_rotated {
    lower(input.kind) == "iamserviceaccountkey"
    not gc_issue["api_key_not_rotated"]
}

api_key_not_rotated = false {
    gc_issue["api_key_not_rotated"]
}

api_key_not_rotated_err = "The API key hasn't been rotated for more than 90 days." {
    gc_issue["api_key_not_rotated"]
}
