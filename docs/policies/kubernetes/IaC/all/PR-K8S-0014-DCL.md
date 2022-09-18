



# Title: Minimize the admission of containers with allowPrivilegeEscalation (PSP)


***<font color="white">Master Test Id:</font>*** TEST_POD_SECURITY_POLICY_7

***<font color="white">Master Snapshot Id:</font>*** ['K8S_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([podSecurityPolicy.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-K8S-0014-DCL|
|eval|data.rule.privilege_escalation|
|message|data.rule.privilege_escalation_err|
|remediationDescription|Create a PSP as described in the Kubernetes documentation, ensuring that the .spec.allowPrivilegeEscalation field is omitted or set to false. References <a href='https://kubernetes.io/docs/concepts/policy/pod-security-policy' target='_blank'>here</a>|
|remediationFunction|PR-K8S-0014-DCL.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Do not generally permit containers to be run with the allowPrivilegeEscalation flag set to true.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS']|
|service|['kubernetesObjectFiles']|


***<font color="white">Resource Types:</font>*** ['podsecuritypolicy']


[podSecurityPolicy.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/kubernetes/iac/podSecurityPolicy.rego
