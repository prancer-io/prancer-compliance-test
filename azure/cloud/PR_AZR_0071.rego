#
# PR-AZR-0071
#

package rule
default rulepass = true

# https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/2017-05-01-preview/diagnosticsettings

rulepass = false {
    lower(input.type) == "microsoft.insights/diagnosticsettings"
    count(input.properties.logs) == 0
}

rulepass = false {
    lower(input.type) == "microsoft.insights/diagnosticsettings"
    input.properties.logs[_].enabled == false
}

metadata := {
    "Policy Code": "PR-AZR-0071",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure storage account logging for queues is disabled (TJX)",
    "Policy Description": "** MODIFICATION OF DEFAULT RULE - As of 12-APR-2019, Queue logging cannot be enabled for Storage Accounts with 'kind' of BlobStorage **_x005F_x000D_ _x005F_x000D_ Storage Logging records details of requests (read, write, and delete operations) against your Azure queues. The logs include additional information such as:_x005F_x000D_ - Timing and server latency._x005F_x000D_ - Success or failure, and HTTP status code._x005F_x000D_ - Authentication details_x005F_x000D_ _x005F_x000D_ This policy identifies Azure storage accounts that do not have logging enabled for queues. As a best practice, enable logging for read, write, and delete request types on queues.",
    "Resource Type": "microsoft.insights/diagnosticsettings",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.insights/2017-05-01-preview/diagnosticsettings"
}
