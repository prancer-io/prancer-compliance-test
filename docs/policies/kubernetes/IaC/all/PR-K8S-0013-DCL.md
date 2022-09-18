



# Title: Minimize the admission of containers wishing to share the host process ID namespace (PSP)


***<font color="white">Master Test Id:</font>*** TEST_POD_SECURITY_POLICY_6

***<font color="white">Master Snapshot Id:</font>*** ['K8S_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([podSecurityPolicy.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-K8S-0013-DCL|
|eval|data.rule.host_pid|
|message|data.rule.host_pid_err|
|remediationDescription|Create a PSP as described in the Kubernetes documentation, ensuring that the .spec.hostPID field is omitted or set to false. References <a href='https://kubernetes.io/docs/concepts/policy/pod-security-policy' target='_blank'>here</a>|
|remediationFunction|PR-K8S-0013-DCL.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>***  Do not generally permit containers to be run with the hostPID flag set to true. A container running in the host's PID namespace can inspect processes running outside the container. If the container also has access to ptrace capabilities this can be used to escalate privileges outside of the container. There should be at least one PodSecurityPolicy (PSP) defined which does not permit containers to share the host PID namespace. If you need to run containers which require hostPID, this should be defined in a separate PSP and you should carefully check RBAC controls to ensure that only limited service accounts and users are given permission to access that PSP.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS']|
|service|['kubernetesObjectFiles']|


***<font color="white">Resource Types:</font>*** ['podsecuritypolicy']


[podSecurityPolicy.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/kubernetes/iac/podSecurityPolicy.rego
