



# Title: Enable AWS Inspector to detect Vulnerability


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-INS-001

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-INS-001|
|eval|data.rule.ins_package|
|message|data.rule.ins_package_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_INS_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Enable AWS Inspector to detect Vulnerability  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['inspector']|


***<font color="white">Resource Types:</font>*** ['aws::inspector::assessmenttemplate']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/all.rego
