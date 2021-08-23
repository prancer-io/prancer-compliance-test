package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites

# PR-AZR-0139-ARM

default https_only = null

azure_attribute_absence ["https_only"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.httpsOnly
}

azure_issue ["https_only"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.httpsOnly != true
}


https_only {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["https_only"]
    not azure_issue["https_only"]
}


https_only = false {
    azure_attribute_absence["https_only"]
}

https_only = false {
    azure_issue["https_only"]
}

https_only_err = "Microsoft.web/Sites resource property httpsOnly missing in the resource" {
    azure_attribute_absence["https_only"]
} else = "Azure App Service Web app does not redirect HTTP to HTTPS" {
    azure_issue["https_only"]
}

https_only_metadata := {
    "Policy Code": "PR-AZR-0139-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure App Service Web app should redirects HTTP to HTTPS",
    "Policy Description": "Azure Web Apps by default allows sites to run under both HTTP and HTTPS, and can be accessed by anyone using non-secure HTTP links. Non-secure HTTP requests can be restricted and all HTTP requests redirected to the secure HTTPS port. We recommend you enforce HTTPS-only traffic to increase security. This will redirect all non-secure HTTP requests to HTTPS ports. HTTPS uses the SSL/TLS protocol to provide a secure connection, which is both encrypted and authenticated.",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}




# PR-AZR-0140-ARM

default min_tls_version = null

azure_attribute_absence ["min_tls_version"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.minTlsVersion
}

azure_issue ["min_tls_version"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.siteConfig.minTlsVersion != "1.2"
}


min_tls_version {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["min_tls_version"]
    not azure_issue["min_tls_version"]
}

min_tls_version = false {
    azure_attribute_absence["min_tls_version"]
}

min_tls_version = false {
    azure_issue["min_tls_version"]
}

min_tls_version_err = "microsoft.web/sites resource property minTlsVersion missing in the resource" {
    azure_attribute_absence["min_tls_version"]
} else = "Web App does not use the latest version of TLS encryption" {
    azure_issue["min_tls_version"]
}

min_tls_version_metadata := {
    "Policy Code": "PR-AZR-0140-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Web App should uses the latest version of TLS encryption",
    "Policy Description": "App service currently allows the web app to set TLS versions 1.0, 1.1 and 1.2. For secure web app connections it is highly recommended to only use the latest TLS 1.2 version.",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}