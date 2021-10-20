package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster

#
# PR-AZR-0006-TRF
#

default aks_cni_net = null

azure_attribute_absence["aks_cni_net"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    not resource.properties.network_profile
}

azure_attribute_absence["aks_cni_net"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    network_profile := resource.properties.network_profile[_]
    not network_profile.network_plugin
}

azure_issue["aks_cni_net"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    network_profile := resource.properties.network_profile[_]
    lower(network_profile.network_plugin) != "azure"
}

aks_cni_net {
    lower(input.resources[_].type) == "azurerm_kubernetes_cluster"
    not azure_attribute_absence["aks_cni_net"]
    not azure_issue["aks_cni_net"]
}

aks_cni_net = false {
    azure_attribute_absence["aks_cni_net"]
}

aks_cni_net = false {
    azure_issue["aks_cni_net"]
}

aks_cni_net_err = "azurerm_kubernetes_cluster property 'network_profile.network_plugin' need to be exist. Currently its missing from the resource. Please set the value to 'azure' after property addition." {
    azure_attribute_absence["aks_cni_net"]
} else = "Azure AKS cluster CNI networking is currently not enabled." {
    azure_issue["aks_cni_net"]
}

aks_cni_net_metadata := {
    "Policy Code": "PR-AZR-0006-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure AKS cluster CNI networking should be enabled",
    "Policy Description": "Azure CNI provides the following features over kubenet networking:</br> </br> - Every pod in the cluster is assigned an IP address in the virtual network. The pods can directly communicate with other pods in the cluster, and other nodes in the virtual network.</br> - Pods in a subnet that have service endpoints enabled can securely connect to Azure services, such as Azure Storage and SQL DB.</br> - You can create user-defined routes (UDR) to route traffic from pods to a Network Virtual Appliance.</br> - Support for Network Policies securing communication between pods.</br> </br> This policy checks your AKS cluster for the Azure CNI network plugin and generates an alert if not found.",
    "Resource Type": "azurerm_kubernetes_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster"
}

#
# PR-AZR-0007-TRF
#

default aks_http_routing = null

azure_attribute_absence["aks_http_routing"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    not resource.properties.addon_profile
}

azure_attribute_absence["aks_http_routing"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    addon_profile := resource.properties.addon_profile[_]
    not addon_profile.http_application_routing
}

azure_attribute_absence["aks_http_routing"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    addon_profile := resource.properties.addon_profile[_]
    http_application_routing := addon_profile.http_application_routing[_]
    not http_application_routing.enabled
}

azure_issue["aks_http_routing"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    addon_profile := resource.properties.addon_profile[_]
    http_application_routing := addon_profile.http_application_routing[_]
    http_application_routing.enabled == true
}

aks_http_routing {
    lower(input.resources[_].type) == "azurerm_kubernetes_cluster"
    not azure_attribute_absence["aks_http_routing"]
    not azure_issue["aks_http_routing"]
}

aks_http_routing = false {
    azure_attribute_absence["aks_http_routing"]
}

aks_http_routing = false {
    azure_issue["aks_http_routing"]
}

aks_http_routing_err = "azurerm_kubernetes_cluster property 'addon_profile.http_application_routing.enabled' need to be exist. Currently its missing from the resource. Please set the value to false after property addition." {
    azure_attribute_absence["aks_http_routing"]
} else = "Azure AKS cluster HTTP application routing is currently not disabled."  {
    azure_issue["aks_http_routing"]
}

aks_http_routing_metadata := {
    "Policy Code": "PR-AZR-0007-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure AKS cluster HTTP application routing should be disabled",
    "Policy Description": "HTTP application routing configures an Ingress controller in your AKS cluster. As applications are deployed, the solution also creates publicly accessible DNS names for application endpoints. While this makes it easy to access applications that are deployed to your Azure AKS cluster, this add-on is not recommended for production use.</br> </br> This policy checks your AKS cluster HTTP application routing add-on setting and alerts if enabled.",
    "Resource Type": "azurerm_kubernetes_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster"
}

#
# PR-AZR-0008-TRF
#

default aks_monitoring = null

aws_attribute_absence["aks_monitoring"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    not resource.properties.addon_profile
}

aws_attribute_absence["aks_monitoring"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    addon_profile := resource.properties.addon_profile[_]
    not addon_profile.oms_agent
}

aws_attribute_absence["aks_monitoring"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    addon_profile := resource.properties.addon_profile[_]
    oms_agent := addon_profile.oms_agent[_]
    not oms_agent.enabled
}

azure_issue["aks_monitoring"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    addon_profile := resource.properties.addon_profile[_]
    oms_agent := addon_profile.oms_agent[_]
    oms_agent.enabled != true
}

aks_monitoring {
    lower(input.resources[_].type) == "azurerm_kubernetes_cluster"
    not azure_attribute_absence["aks_monitoring"]
    not azure_issue["aks_monitoring"]
}

aks_monitoring = false {
    azure_attribute_absence["aks_monitoring"]
}

aks_monitoring = false {
    azure_issue["aks_monitoring"]
} 

aks_monitoring_err = "azurerm_kubernetes_cluster property 'addon_profile.oms_agent.enabled' need to be exist. Currently its missing from the resource. Please set the value to true after property addition." {
    azure_attribute_absence["aks_monitoring"]
    
} else = "Azure AKS cluster monitoring is currently not enabled." {
    azure_issue["aks_monitoring"]
}

aks_monitoring_metadata := {
    "Policy Code": "PR-AZR-0008-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure AKS cluster monitoring should be enabled",
    "Policy Description": "Azure Monitor for containers is a feature designed to monitor the performance of container workloads deployed to either Azure Container Instances or managed Kubernetes clusters hosted on Azure Kubernetes Service (AKS). Monitoring your containers is critical, especially when you're running a production cluster, at scale, with multiple applications.</br> </br> This policy checks your AKS cluster monitoring add-on setting and alerts if no configuration is found, or monitoring is disabled.",
    "Resource Type": "azurerm_kubernetes_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster"
}

#
# PR-AZR-0009-TRF
#

default aks_nodes = null

azure_attribute_absence["aks_nodes"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    not resource.properties.default_node_pool
}

#azure_attribute_absence["aks_nodes"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_kubernetes_cluster"
#    count(resource.properties.default_node_pool) == 0
#}

azure_attribute_absence["aks_nodes"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    default_node_pool := resource.properties.default_node_pool[_]
    not default_node_pool.node_count
}

azure_issue["aks_nodes"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    default_node_pool := resource.properties.default_node_pool[_]
    to_number(default_node_pool.node_count) < 3
}

aks_nodes {
    lower(input.resources[_].type) == "azurerm_kubernetes_cluster"
    not azure_attribute_absence["aks_nodes"]
    not azure_issue["aks_nodes"]
}

aks_nodes = false {
    azure_attribute_absence["aks_nodes"]
}

aks_nodes = false {
    azure_issue["aks_nodes"]
} 

aks_nodes_err = "azurerm_kubernetes_cluster property 'default_node_pool.node_count' need to be exist. Currently its missing from the resource. Please set the minimum value as 3 after property addition." {
    azure_attribute_absence["aks_nodes"]
} else = "Azure AKS cluster pool profile currenlty does not have minimum 3 or more nodes." {
    azure_issue["aks_nodes"]
}

aks_nodes_metadata := {
    "Policy Code": "PR-AZR-0009-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure AKS cluster pool profile should have minimum 3 or more nodes",
    "Policy Description": "Ensure your AKS cluster pool profile contains minimum 3 or more nodes. This is recommended for a more resilient cluster. (Clusters smaller than 3 may experience downtime during upgrades.)</br> </br> This policy checks the size of your cluster pool profiles and alerts if there are fewer than 3 nodes.",
    "Resource Type": "azurerm_kubernetes_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster"
}

#
# PR-AZR-0010-TRF
#

default aks_rbac = null

azure_attribute_absence["aks_rbac"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    not resource.properties.role_based_access_control
}

#azure_attribute_absence["aks_rbac"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_kubernetes_cluster"
#    count(resource.properties.role_based_access_control) == 0
#}

azure_attribute_absence["aks_rbac"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    role_based_access_control := resource.properties.role_based_access_control[_]
    not role_based_access_control.enabled
}

azure_issue["aks_rbac"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    role_based_access_control := resource.properties.role_based_access_control[_]
    role_based_access_control.enabled != true
}

aks_rbac {
    lower(input.resources[_].type) == "azurerm_kubernetes_cluster"
    not azure_attribute_absence["aks_rbac"]
    not azure_issue["aks_rbac"]
}

aks_rbac = false {
    azure_attribute_absence["aks_rbac"]
}

aks_rbac = false {
    azure_issue["aks_rbac"]
} 

aks_rbac_err = "azurerm_kubernetes_cluster property 'role_based_access_control.enabled' need to be exist. Currently its missing from the resource. Please set the value to true after property addition." {
    azure_attribute_absence["aks_rbac"]
} else = "Azure AKS role-based access control (RBAC) is not enforced." {
    azure_issue["aks_rbac"]
}

aks_rbac_metadata := {
    "Policy Code": "PR-AZR-0010-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure AKS role-based access control (RBAC) should be enforced",
    "Policy Description": "To provide granular filtering of the actions that users can perform, Kubernetes uses role-based access controls (RBAC). This control mechanism lets you assign users, or groups of users, permission to do things like create or modify resources, or view logs from running application workloads. These permissions can be scoped to a single namespace, or granted across the entire AKS cluster.</br> </br> This policy checks your AKS cluster RBAC setting and alerts if disabled.",
    "Resource Type": "azurerm_kubernetes_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster"
}

#
# PR-AZR-0101-TRF
#

default aks_aad_rbac_enabled = null

azure_attribute_absence["aks_aad_rbac_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    #not resource.properties.role_based_access_control.azure_active_directory.managed
    not resource.properties.role_based_access_control
}

azure_attribute_absence["aks_aad_rbac_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    role_based_access_control := resource.properties.role_based_access_control[_]
    not role_based_access_control.azure_active_directory
}

azure_attribute_absence["aks_aad_rbac_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    role_based_access_control := resource.properties.role_based_access_control[_]
    azure_active_directory := role_based_access_control.azure_active_directory[_]
    not azure_active_directory.managed
}

azure_attribute_absence["aks_aad_rbac_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    #not resource.properties.role_based_access_control.azure_active_directory.azure_rbac_enabled
    role_based_access_control := resource.properties.role_based_access_control[_]
    azure_active_directory := role_based_access_control.azure_active_directory[_]
    not azure_active_directory.azure_rbac_enabled
}

azure_issue["aks_aad_rbac_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    role_based_access_control := resource.properties.role_based_access_control[_]
    azure_active_directory := role_based_access_control.azure_active_directory[_]
    azure_active_directory.managed != true
} 

azure_issue["aks_aad_rbac_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    role_based_access_control := resource.properties.role_based_access_control[_]
    azure_active_directory := role_based_access_control.azure_active_directory[_]
    azure_active_directory.azure_rbac_enabled != true
}

aks_aad_rbac_enabled {
    lower(input.resources[_].type) == "azurerm_kubernetes_cluster"
    not azure_attribute_absence["aks_aad_rbac_enabled"]
    not azure_issue["aks_aad_rbac_enabled"]
}

aks_aad_rbac_enabled = false {
    azure_attribute_absence["aks_aad_rbac_enabled"]
} 

aks_aad_rbac_enabled = false {
    azure_issue["aks_aad_rbac_enabled"]
} 

aks_aad_rbac_enabled_err = "azurerm_kubernetes_cluster property 'role_based_access_control.azure_active_directory.managed' and 'role_based_access_control.azure_active_directory.azure_rbac_enabled' need to be exist. those are missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["aks_aad_rbac_enabled"]
} else = "Managed Azure AD RBAC for AKS cluster is not enabled" {
    azure_issue["aks_aad_rbac_enabled"]
}

aks_aad_rbac_enabled_metadata := {
    "Policy Code": "PR-AZR-0101-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Managed Azure AD RBAC for AKS cluster should be enabled",
    "Policy Description": "Azure Kubernetes Service (AKS) can be configured to use Azure Active Directory (AD) for user authentication. In this configuration, you sign in to an AKS cluster using an Azure AD authentication token. You can also configure Kubernetes role-based access control (Kubernetes RBAC) to limit access to cluster resources based a user's identity or group membership. This policy checks your AKS cluster Azure Active Directory (AD) RBAC setting and alerts if disabled.",
    "Resource Type": "azurerm_kubernetes_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster"
}

#
# PR-AZR-0138-TRF
#

default aks_network_policy_configured = null

azure_attribute_absence["aks_network_policy_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    network_profile := resource.properties.network_profile[_]
    not network_profile.network_policy
}

azure_issue["aks_network_policy_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    network_profile := resource.properties.network_profile[_]
    lower(network_profile.network_policy) != "azure"
}

aks_network_policy_configured {
    lower(input.resources[_].type) == "azurerm_kubernetes_cluster"
    not azure_attribute_absence["aks_network_policy_configured"]
    not azure_issue["aks_network_policy_configured"]
}

aks_network_policy_configured = false {
    azure_issue["aks_network_policy_configured"]
}

aks_network_policy_configured = false {
    azure_attribute_absence["aks_network_policy_configured"]
}

aks_network_policy_configured_err = "azurerm_kubernetes_cluster property 'network_profile.network_policy' is missing from the resource" {
    azure_attribute_absence["aks_network_policy_configured"]
} else = "AKS cluster currently dont have Network Policy configured" {
    azure_issue["aks_network_policy_configured"]
}

aks_network_policy_configured_metadata := {
    "Policy Code": "PR-AZR-0138-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "AKS cluster shoud have Network Policy configured",
    "Policy Description": "Network policy used for building Kubernetes network. - calico or azure.",
    "Resource Type": "azurerm_kubernetes_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/1.43.0/docs/data-sources/kubernetes_cluster
# PR-AZR-0137-TRF
#

default aks_api_server_authorized_ip_range_enabled = null

azure_attribute_absence["aks_api_server_authorized_ip_range_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    not resource.properties.api_server_authorized_ip_ranges
}

azure_issue["aks_api_server_authorized_ip_range_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    count(resource.properties.api_server_authorized_ip_ranges) == 0
}

aks_api_server_authorized_ip_range_enabled {
    lower(input.resources[_].type) == "azurerm_kubernetes_cluster"
    not azure_attribute_absence["aks_api_server_authorized_ip_range_enabled"]
    not azure_issue["aks_api_server_authorized_ip_range_enabled"]
}

aks_api_server_authorized_ip_range_enabled = false {
    azure_issue["aks_api_server_authorized_ip_range_enabled"]
}

aks_api_server_authorized_ip_range_enabled = false {
    azure_attribute_absence["aks_api_server_authorized_ip_range_enabled"]
}

aks_api_server_authorized_ip_range_enabled_err = "azurerm_kubernetes_cluster property 'api_server_authorized_ip_ranges' is missing from the resource" {
    azure_attribute_absence["aks_api_server_authorized_ip_range_enabled"]
} else = "AKS cluster currently dont have Authorized IP Ranges enabled" {
    azure_issue["aks_api_server_authorized_ip_range_enabled"]
}

aks_api_server_authorized_ip_range_enabled_metadata := {
    "Policy Code": "PR-AZR-0137-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "AKS shoud have an API Server Authorized IP Ranges enabled",
    "Policy Description": "Authorized IP Ranges to kubernetes API server",
    "Resource Type": "azurerm_kubernetes_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster"
}


# https://www.danielstechblog.io/disable-the-kubernetes-dashboard-on-azure-kubernetes-service/
# PR-AZR-0144-TRF
#

default aks_kub_dashboard_disabled = null

azure_attribute_absence["aks_kub_dashboard_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    addon_profile := resource.properties.addon_profile[_]
    kube_dashboard := addon_profile.kube_dashboard[_]
    not kube_dashboard.enabled
}

azure_issue["aks_kub_dashboard_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    addon_profile := resource.properties.addon_profile[_]
    kube_dashboard := addon_profile.kube_dashboard[_]
    kube_dashboard.enabled == true
}

aks_kub_dashboard_disabled {
    lower(input.resources[_].type) == "azurerm_kubernetes_cluster"
    not azure_attribute_absence["aks_kub_dashboard_disabled"]
    not azure_issue["aks_kub_dashboard_disabled"]
}

aks_kub_dashboard_disabled = false {
    azure_issue["aks_kub_dashboard_disabled"]
}

aks_kub_dashboard_disabled {
    lower(input.resources[_].type) == "azurerm_kubernetes_cluster"
    azure_attribute_absence["aks_kub_dashboard_disabled"]
    not azure_issue["aks_kub_dashboard_disabled"]
}

aks_kub_dashboard_disabled_err = "Kubernetes Dashboard is currently not disabled" {
    azure_issue["aks_kub_dashboard_disabled"]
}

aks_kub_dashboard_disabled_metadata := {
    "Policy Code": "PR-AZR-0144-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Kubernetes Dashboard shoud be disabled",
    "Policy Description": "Disable the Kubernetes dashboard on Azure Kubernetes Service",
    "Resource Type": "azurerm_kubernetes_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster"
}
