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
# Id: 301
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

#
# Id: 302
#

default k8s_client_cert = null

gc_issue["k8s_client_cert"] {
    resource := input.json.resources[_]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.masterAuth.clientKey
}

gc_issue["k8s_client_cert"] {
    resource := input.json.resources[_]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.masterAuth.clientCertificate
}

k8s_client_cert {
    lower(input.json.resources[_].type) == "container.v1.cluster"
    not gc_issue["k8s_client_cert"]
}

k8s_client_cert = false {
    gc_issue["k8s_client_cert"]
}

k8s_client_cert_err = "GCP Kubernetes Engine Clusters Client Certificate is set to Disabled" {
    gc_issue["k8s_client_cert"]
}

#
# Id: 303
#

default k8s_alias_ip = null

gc_issue["k8s_alias_ip"] {
    resource := input.json.resources[_]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.ipAllocationPolicy.useIpAliases
}

k8s_alias_ip {
    lower(input.json.resources[_].type) == "container.v1.cluster"
    not gc_issue["k8s_alias_ip"]
}

k8s_alias_ip = false {
    gc_issue["k8s_alias_ip"]
}

k8s_alias_ip_err = "GCP Kubernetes Engine Clusters have Alias IP disabled" {
    gc_issue["k8s_alias_ip"]
}

#
# Id: 304
#

default k8s_alpha = null

gc_issue["k8s_alpha"] {
    resource := input.json.resources[_]
    lower(resource.type) == "container.v1.cluster"
    resource.properties.enableKubernetesAlpha
}

k8s_alpha {
    lower(input.json.resources[_].type) == "container.v1.cluster"
    not gc_issue["k8s_alpha"]
}

k8s_alpha = false {
    gc_issue["k8s_alpha"]
}

k8s_alpha_err = "GCP Kubernetes Engine Clusters have Alpha cluster feature enabled" {
    gc_issue["k8s_alpha"]
}

#
# Id: 305
#

default k8s_http_lbs = null

gc_issue["k8s_http_lbs"] {
    resource := input.json.resources[_]
    lower(resource.type) == "container.v1.cluster"
    resource.properties.addonsConfig.httpLoadBalancing.disabled
}

k8s_http_lbs {
    lower(input.json.resources[_].type) == "container.v1.cluster"
    not gc_issue["k8s_http_lbs"]
}

k8s_http_lbs = false {
    gc_issue["k8s_http_lbs"]
}

k8s_http_lbs_err = "GCP Kubernetes Engine Clusters have HTTP load balancing disabled" {
    gc_issue["k8s_http_lbs"]
}

#
# Id: 306
#

default k8s_legacy_abac = null

gc_issue["k8s_legacy_abac"] {
    resource := input.json.resources[_]
    lower(resource.type) == "container.v1.cluster"
    resource.properties.legacyAbac.enabled
}

k8s_legacy_abac {
    lower(input.json.resources[_].type) == "container.v1.cluster"
    not gc_issue["k8s_legacy_abac"]
}

k8s_legacy_abac = false {
    gc_issue["k8s_legacy_abac"]
}

k8s_legacy_abac_err = "GCP Kubernetes Engine Clusters have Legacy Authorization enabled" {
    gc_issue["k8s_legacy_abac"]
}

#
# Id: 307
#

default k8s_master_auth_net = null

gc_issue["k8s_master_auth_net"] {
    resource := input.json.resources[_]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.masterAuthorizedNetworksConfig.enabled
}

k8s_master_auth_net {
    lower(input.json.resources[_].type) == "container.v1.cluster"
    not gc_issue["k8s_master_auth_net"]
}

k8s_master_auth_net = false {
    gc_issue["k8s_master_auth_net"]
}

k8s_master_auth_net_err = "GCP Kubernetes Engine Clusters have Master authorized networks disabled" {
    gc_issue["k8s_master_auth_net"]
}

#
# Id: 308
#

default k8s_net_policy = null

gc_issue["k8s_net_policy"] {
    resource := input.json.resources[_]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.networkPolicy.enabled
}

k8s_net_policy {
    lower(input.json.resources[_].type) == "container.v1.cluster"
    not gc_issue["k8s_net_policy"]
}

k8s_net_policy = false {
    gc_issue["k8s_net_policy"]
}

k8s_net_policy_err = "GCP Kubernetes Engine Clusters have Network policy disabled" {
    gc_issue["k8s_net_policy"]
}

#
# Id: 309
#

default k8s_logging = null

gc_attribute_absence["k8s_logging"] {
    resource := input.json.resources[_]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.loggingService
}

gc_issue["k8s_logging"] {
    resource := input.json.resources[_]
    lower(resource.type) == "container.v1.cluster"
    lower(resource.properties.loggingService) == "none"
}

k8s_logging {
    lower(input.json.resources[_].type) == "container.v1.cluster"
    not gc_issue["k8s_logging"]
    not gc_attribute_absence["k8s_logging"]
}

k8s_logging = false {
    gc_issue["k8s_logging"]
}

k8s_logging = false {
    gc_attribute_absence["k8s_logging"]
}

k8s_logging_err = "GCP Kubernetes Engine Clusters have Stackdriver Logging disabled" {
    gc_issue["k8s_logging"]
}

k8s_logging_miss_err = "Kubernetes Engine Cluster attribute loggingService config missing in the resource" {
    gc_attribute_absence["k8s_logging"]
}

#
# Id: 310
#

default k8s_monitor = null

gc_attribute_absence["k8s_monitor"] {
    resource := input.json.resources[_]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.monitoringService
}

gc_issue["k8s_monitor"] {
    resource := input.json.resources[_]
    lower(resource.type) == "container.v1.cluster"
    lower(resource.properties.monitoringService) == "none"
}

k8s_monitor {
    lower(input.json.resources[_].type) == "container.v1.cluster"
    not gc_issue["k8s_monitor"]
    not gc_attribute_absence["k8s_monitor"]
}

k8s_monitor = false {
    gc_issue["k8s_monitor"]
}

k8s_monitor = false {
    gc_attribute_absence["k8s_monitor"]
}

k8s_monitor_err = "GCP Kubernetes Engine Clusters have Stackdriver Monitoring disabled" {
    gc_issue["k8s_monitor"]
}

k8s_monitor_miss_err = "Kubernetes Engine Cluster attribute monitoringService config missing in the resource" {
    gc_attribute_absence["k8s_monitor"]
}

#
# Id: 311
#

default k8s_binary_auth = null

gc_issue["k8s_binary_auth"] {
    resource := input.json.resources[_]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.binaryAuthorization.enabled
}

k8s_binary_auth {
    lower(input.json.resources[_].type) == "container.v1.cluster"
    not gc_issue["k8s_binary_auth"]
}

k8s_binary_auth = false {
    gc_issue["k8s_binary_auth"]
}

k8s_binary_auth_err = "GCP Kubernetes Engine Clusters have binary authorization disabled" {
    gc_issue["k8s_binary_auth"]
}

#
# Id: 312
#

default k8s_legacy_endpoint = null

gc_issue["k8s_legacy_endpoint"] {
    resource := input.json.resources[_]
    lower(resource.type) == "container.v1.cluster"
    resource.properties.nodeConfig.metadata["disable-legacy-endpoints"]
}

k8s_legacy_endpoint {
    lower(input.json.resources[_].type) == "container.v1.cluster"
    not gc_issue["k8s_legacy_endpoint"]
}

k8s_legacy_endpoint = false {
    gc_issue["k8s_legacy_endpoint"]
}

k8s_legacy_endpoint_err = "GCP Kubernetes Engine Clusters have legacy compute engine metadata endpoints enabled" {
    gc_issue["k8s_legacy_endpoint"]
}

#
# Id: 313
#

default k8s_pod_security = null

gc_issue["k8s_pod_security"] {
    resource := input.json.resources[_]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.podSecurityPolicyConfig.enabled
}

k8s_pod_security {
    lower(input.json.resources[_].type) == "container.v1.cluster"
    not gc_issue["k8s_pod_security"]
}

k8s_pod_security = false {
    gc_issue["k8s_pod_security"]
}

k8s_pod_security_err = "GCP Kubernetes Engine Clusters have pod security policy disabled" {
    gc_issue["k8s_pod_security"]
}

#
# Id: 315
#

default k8s_egress_metering = null

gc_issue["k8s_egress_metering"] {
    resource := input.json.resources[_]
    lower(resource.type) == "container.v1.cluster"
    not resource.properties.resourceUsageExportConfig.enableNetworkEgressMetering
}

k8s_egress_metering {
    lower(input.json.resources[_].type) == "container.v1.cluster"
    not gc_issue["k8s_egress_metering"]
}

k8s_egress_metering = false {
    gc_issue["k8s_egress_metering"]
}

k8s_egress_metering_err = "GCP Kubernetes Engine Clusters not configured with network traffic egress metering" {
    gc_issue["k8s_egress_metering"]
}
