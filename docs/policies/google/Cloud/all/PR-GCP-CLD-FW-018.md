



# Title: Ensure GCP Firewall rule logging is enabled


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-FW-018

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_FIREWALL']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([compute.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-FW-018|
|eval|data.rule.firewall_logging|
|message|data.rule.firewall_logging_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/compute/docs/reference/rest/v1/firewalls' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_FW_018.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies GCP firewall rules that are not configured with firewall rule logging.  Firewall Rules Logging lets you audit, verify, and analyze the effects of your firewall rules. When you enable logging for a firewall rule, Google Cloud creates an entry called a connection record each time the rule allows or denies traffic. 

Reference: https://cloud.google.com/vpc/docs/firewall-rules-logging  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|[]|
|service|['compute']|



[compute.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/compute.rego
