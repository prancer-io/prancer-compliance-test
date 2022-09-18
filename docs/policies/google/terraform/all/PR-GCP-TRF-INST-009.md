



# Title: Ensure GCP HTTPS Load balancer SSL Policy is using restrictive profile


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-INST-009

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.v1.sslpolicy.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-INST-009|
|eval|data.rule.compute_ssl_profile_restricted|
|message|data.rule.compute_ssl_profile_restricted_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/compute/docs/reference/rest/v1/instances' target='_blank'>here</a>|
|remediationFunction|PR_GCP_TRF_INST_009.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies HTTPS Load balancers which are not using restrictive profile in it's SSL Policy, which controls sets of features used in negotiating SSL with clients. As a best security practice, use RESTRICTED as SSL policy profile as it meets stricter compliance requirements and does not include any out-of-date SSL features.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA-CCM', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_compute_ssl_policy']


[compute.v1.sslpolicy.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/compute.v1.sslpolicy.rego
