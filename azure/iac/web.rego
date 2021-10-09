package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites

# PR-AZR-0139-ARM

default https_only = null

azure_attribute_absence ["https_only"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.httpsOnly
}

source_path[{"https_only":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.httpsOnly
    metadata:= {
        "resource_path": [["resources",i,"properties","httpsOnly"]]
    }
}

azure_issue ["https_only"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.httpsOnly != true
}

source_path[{"https_only":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.httpsOnly != true
    metadata:= {
        "resource_path": [["resources",i,"properties","httpsOnly"]]
    }
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
    "Policy Title": "Ensure Azure App Service Web App enforce https connection",
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

source_path[{"min_tls_version":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.minTlsVersion
    metadata:= {
        "resource_path": [["resources",i,"properties","siteConfig","minTlsVersion"]]
    }
}

azure_issue ["min_tls_version"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.siteConfig.minTlsVersion != "1.2"
}

source_path[{"min_tls_version":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.siteConfig.minTlsVersion != "1.2"
    metadata:= {
        "resource_path": [["resources",i,"properties","siteConfig","minTlsVersion"]]
    }
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




# PR-AZR-0141-ARM

default client_cert_enabled = null

azure_attribute_absence ["client_cert_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.clientCertEnabled
}

source_path[{"client_cert_enabled":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.clientCertEnabled
    metadata:= {
        "resource_path": [["resources",i,"properties","clientCertEnabled"]]
    }
}

azure_issue ["client_cert_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.clientCertEnabled != true
}

source_path[{"client_cert_enabled":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.clientCertEnabled != true
    metadata:= {
        "resource_path": [["resources",i,"properties","clientCertEnabled"]]
    }
}


client_cert_enabled {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["client_cert_enabled"]
    not azure_issue["client_cert_enabled"]
}

client_cert_enabled = false {
    azure_attribute_absence["client_cert_enabled"]
}

client_cert_enabled = false {
    azure_issue["client_cert_enabled"]
}

client_cert_enabled_err = "microsoft.web/sites resource property clientCertEnabled missing in the resource" {
    azure_attribute_absence["client_cert_enabled"]
} else = "Web App does not have incoming client certificates enabled" {
    azure_issue["client_cert_enabled"]
}

client_cert_enabled_metadata := {
    "Policy Code": "PR-AZR-0141-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Web App should has incoming client certificates enabled",
    "Policy Description": "Client certificates allow the Web App to require a certificate for incoming requests. Only clients that have a valid certificate will be able to reach the app. The TLS mutual authentication technique in enterprise environments ensures the authenticity of clients to the server. If incoming client certificates are enabled only an authenticated client with valid certificates can access the app.",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}





# PR-AZR-0142-ARM

default http_20_enabled = null

azure_attribute_absence ["http_20_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.http20Enabled
}

source_path[{"http_20_enabled":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.http20Enabled
    metadata:= {
        "resource_path": [["resources",i,"properties","siteConfig","http20Enabled"]]
    }
}

azure_issue ["http_20_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.siteConfig.http20Enabled != true
}

source_path[{"http_20_enabled":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.siteConfig.http20Enabled != true
    metadata:= {
        "resource_path": [["resources",i,"properties","siteConfig","http20Enabled"]]
    }
}


http_20_enabled {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["http_20_enabled"]
    not azure_issue["http_20_enabled"]
}

http_20_enabled = false {
    azure_attribute_absence["http_20_enabled"]
}

http_20_enabled = false {
    azure_issue["http_20_enabled"]
}

http_20_enabled_err = "microsoft.web/sites resource property http20Enabled missing in the resource" {
    azure_attribute_absence["http_20_enabled"]
} else = "Web App does not use the latest version of HTTP" {
    azure_issue["http_20_enabled"]
}

http_20_enabled_metadata := {
    "Policy Code": "PR-AZR-0142-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Web App should uses the latest version of HTTP",
    "Policy Description": "We recommend you use the latest HTTP version for web apps and take advantage of any security fixes and new functionalities featured. With each software installation you can determine if a given update meets your organization's requirements. Organizations should verify the compatibility and support provided for any additional software, assessing the current version against the update revision being considered.",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}