package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
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