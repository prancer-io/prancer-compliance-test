



# Title: Ensure,  GCP Load balancer HTTPS target proxy configured with default SSL policy rather than custom SSL policy


***<font color="white">Master Test Id:</font>*** PR-GCP-GDF-THP-001

***<font color="white">Master Snapshot Id:</font>*** ['GDF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-GDF-THP-001|
|eval|data.rule.lbs_ssl_policy|
|message|data.rule.lbs_ssl_policy_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/compute/docs/reference/rest/v1/targetHttpsProxies' target='_blank'>here</a>|
|remediationFunction|PR_GCP_GDF_THP_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies Load balancer HTTPS target proxies which are configured with default SSL Policy instead of custom SSL policy. It is a best practice to use custom SSL policy to access load balancers. It gives you closer control over SSL/TLS versions and ciphers.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS', 'CSA-CCM', 'HITRUST']|
|service|['deploymentmanager']|


***<font color="white">Resource Types:</font>*** ['compute.v1.targethttpsproxy']


[compute.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/iac/compute.rego
