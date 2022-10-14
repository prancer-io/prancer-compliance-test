



# Title: Enable AWS Inspector to detect Vulnerability


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-INS-001

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ALL_15']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-INS-001|
|eval|data.rule.ins_package|
|message|data.rule.ins_package_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_INS_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Enable AWS Inspector to detect Vulnerability  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|[]|
|service|['inspector']|



[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
