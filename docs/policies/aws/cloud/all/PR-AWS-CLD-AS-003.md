



# Master Test ID: PR-AWS-CLD-AS-003


***<font color="white">Master Snapshot Id:</font>*** ['TEST_ALL_07']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-AS-003|
|eval|data.rule.as_http_token|
|message|data.rule.as_http_token_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/cli/latest/reference/autoscaling/describe-launch-configurations.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_AS_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure EC2 Auto Scaling Group does not launch IMDSv1

***<font color="white">Description:</font>*** This control checks if EC2 instances use IMDSv1 instead of IMDSv2, this also applies to instances created in the ASG.IMDSv1 is vulnerable to Server Side Request Forgery (SSRF) vulnerabilities in web applications running on EC2, open Website Application Firewalls, open reverse proxies, and open layer 3 firewalls and NATs. IMDSv2 uses session-oriented requests every request is now protected by session authentication.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|[]|
|service|['auto scaling']|



[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
