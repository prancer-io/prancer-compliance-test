



# Title: Minimize the admission of root containers (PSP)


***<font color="white">Master Test Id:</font>*** TEST_POD_SECURITY_POLICY_2

***<font color="white">Master Snapshot Id:</font>*** ['K8S_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([podSecurityPolicy.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-K8S-0009-DCL|
|eval|data.rule.run_as_root|
|message|data.rule.run_as_root_err|
|remediationDescription|Create a PSP as described in the Kubernetes documentation, ensuring that the .spec.runAsUser.rule is set to either MustRunAsNonRoot or MustRunAs with the range of UIDs not including 0.  References <a href='https://kubernetes.io/docs/concepts/policy/pod-security-policy/#enabling-pod-security-policies' target='_blank'>here</a>|
|remediationFunction|PR-K8S-0009-DCL.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Do not generally permit containers to be run as the root user. Containers may run as any Linux user. Containers which run as the root user, whilst constrained by Container Runtime security features still have a escalated likelihood of container breakout. Ideally, all containers should run as a defined non-UID 0 user. There should be at least one PodSecurityPolicy (PSP) defined which does not permit root users in a container. If you need to run root containers, this should be defined in a separate PSP and you should carefully check RBAC controls to ensure that only limited service accounts and users are given permission to access that PSP.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS']|
|service|['kubernetesObjectFiles']|


***<font color="white">Resource Types:</font>*** ['podsecuritypolicy']


[podSecurityPolicy.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/kubernetes/iac/podSecurityPolicy.rego
