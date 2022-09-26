



# Title: Ensure that the cluster-admin role is only used where required (RBAC)


***<font color="white">Master Test Id:</font>*** TEST_ROLE_BINDING_2

***<font color="white">Master Snapshot Id:</font>*** ['K8S_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([roleBinding.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-K8S-0004-DCL|
|eval|data.rule.admin_role|
|message|data.rule.admin_role_err|
|remediationDescription|Identify all clusterrolebindings to the cluster-admin role. Check if they are used and if they need this role or if they could use a role with fewer privileges. Where possible, first bind users to a lower privileged role and then remove the clusterrolebinding to the cluster-admin role : kubectl delete clusterrolebinding [name]|
|remediationFunction|PR-K8S-0004-DCL.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** The RBAC role cluster-admin provides wide-ranging powers over the environment and should be used only where and when needed. Kubernetes provides a set of default roles where RBAC is used. Some of these roles such as cluster-admin provide wide-ranging privileges which should only be applied where absolutely necessary. Roles such as cluster-admin allow super-user access to perform any action on any resource. When used in a ClusterRoleBinding, it gives full control over every resource in the cluster and in all namespaces. When used in a RoleBinding, it gives full control over every resource in the rolebinding's namespace, including the namespace itself.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS']|
|service|['kubernetesObjectFiles']|


***<font color="white">Resource Types:</font>*** ['rolebinding', 'clusterrolebinding']


[roleBinding.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/kubernetes/iac/roleBinding.rego
