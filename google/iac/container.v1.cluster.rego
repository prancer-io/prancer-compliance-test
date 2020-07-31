package rule

# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters

#
# Id: 300
#

default k8s_svc_account = null

gc_attribute_absence["k8s_svc_account"] {
    resource := input.json.resources[_]
    lower(resource.type) == "container.v1.cluster"
    count([c | r = resource.properties.nodePools[_].config; c := 1]) == 0
}

gc_issue["k8s_svc_account"] {
    resource := input.json.resources[_]
    lower(resource.type) == "container.v1.cluster"
    resource.properties.nodePools[_].config.serviceAccount == "default"
}

k8s_svc_account {
    lower(input.json.resources[_].type) == "container.v1.cluster"
    not gc_issue["k8s_svc_account"]
    not gc_attribute_absence["k8s_svc_account"]
}

k8s_svc_account = false {
    gc_issue["k8s_svc_account"]
}

k8s_svc_account = false {
    gc_attribute_absence["k8s_svc_account"]
}

k8s_svc_account_err = "GCP Kubernetes Engine Cluster Nodes have default Service account for Project access" {
    gc_issue["k8s_svc_account"]
}

k8s_svc_account_miss_err = "Kubernetes Engine Cluster attribute nodePools config missing in the resource" {
    gc_attribute_absence["k8s_svc_account"]
}

#
# 301
#

default k8s_basicauth = null

gc_issue["k8s_basicauth"] {
    resource := input.json.resources[_]
    lower(resource.type) == "container.v1.cluster"
    count(resource.properties.masterAuth.username) > 0
}

gc_issue["k8s_basicauth"] {
    resource := input.json.resources[_]
    lower(resource.type) == "container.v1.cluster"
    count(resource.properties.masterAuth.password) > 0
}

k8s_basicauth {
    lower(input.json.resources[_].type) == "container.v1.cluster"
    not gc_issue["k8s_basicauth"]
}

k8s_basicauth = false {
    gc_issue["k8s_basicauth"]
}

k8s_basicauth_err = "GCP Kubernetes Engine Clusters Basic Authentication is set to Enabled" {
    gc_issue["k8s_basicauth"]
}
