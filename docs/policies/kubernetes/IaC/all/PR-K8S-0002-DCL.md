



# Title: Minimize wildcard use in Roles and ClusterRoles (RBAC)


***<font color="white">Master Test Id:</font>*** TEST_ROLE_2

***<font color="white">Master Snapshot Id:</font>*** ['K8S_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([role.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-K8S-0002-DCL|
|eval|data.rule.rbac_wildcard|
|message|data.rule.rbac_wildcard_err|
|remediationDescription|Where possible, remove get, list and watch access to secret objects in the cluster.|
|remediationFunction|PR-K8S-0002-DCL.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Kubernetes Roles and ClusterRoles provide access to resources based on sets of objects and actions that can be taken on those objects. It is possible to set either of these to be the wildcard " * " which matches all items. Use of wildcards is not optimal from a security perspective as it may allow for inadvertent access to be granted when new resources are added to the Kubernetes API either as CRDs or in later versions of the product. The principle of least privilege recommends that users are provided only the access required for their role and nothing more. The use of wildcard rights grants is likely to provide excessive rights to the Kubernetes API.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS']|
|service|['kubernetesObjectFiles']|


***<font color="white">Resource Types:</font>*** ['role', 'clusterrole']


[role.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/kubernetes/iac/role.rego
