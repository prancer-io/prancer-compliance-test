package rule

# https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances

#
# Id: 332
#

default sql_labels = null

gc_issue["sql_labels"] {
    resource := input.json.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    not resource.properties.settings.userLabels
}

gc_issue["sql_labels"] {
    resource := input.json.resources[_]
    lower(resource.type) == "sqladmin.v1beta4.instance"
    count(resource.properties.settings.userLabels) == 0
}

sql_labels {
    lower(input.json.resources[_].type) == "sqladmin.v1beta4.instance"
    not gc_issue["sql_labels"]
}

sql_labels = false {
    gc_issue["sql_labels"]
}

sql_labels_err = "GCP SQL Instances without any Label information" {
    gc_issue["sql_labels"]
}
