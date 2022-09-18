



# Title: Ensure AppSync is configured with AWS Web Application Firewall v2.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-APS-001

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-APS-001|
|eval|data.rule.appsync_not_configured_with_firewall_v2|
|message|data.rule.appsync_not_configured_with_firewall_v2_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appsync-graphqlapi.html#aws-resource-appsync-graphqlapi--examples' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_APS_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Enable the AWS WAF service on AppSync to protect against application layer attacks. To block malicious requests to your AppSync, define the block criteria in the WAF web access control list (web ACL).  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['NIST 800', 'GDPR', 'CIS', 'ISO 27001', 'LGPD', 'HITRUST', 'HIPAA']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::appsync::graphqlapi', 'aws::wafregional::webaclassociation']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/all.rego
