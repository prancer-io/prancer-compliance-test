



# Title: Ensure EC2 Auto Scaling Group does not launch IMDSv1


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-AS-003

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-AS-003|
|eval|data.rule.as_http_token|
|message|data.rule.as_http_token_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-launchconfiguration-metadataoptions.html#cfn-autoscaling-launchconfiguration-metadataoptions-httptokens' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_AS_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This control checks if EC2 instances use IMDSv1 instead of IMDSv2, this also applies to instances created in the ASG.IMDSv1 is vulnerable to Server Side Request Forgery (SSRF) vulnerabilities in web applications running on EC2, open Website Application Firewalls, open reverse proxies, and open layer 3 firewalls and NATs. IMDSv2 uses session-oriented requests every request is now protected by session authentication.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::autoscaling::launchconfiguration']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/all.rego
