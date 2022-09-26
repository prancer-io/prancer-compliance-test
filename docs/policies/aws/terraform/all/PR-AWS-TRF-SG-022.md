



# Title: Ensure AWS resources that support tags have Tags


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-SG-022

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([securitygroup.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-SG-022|
|eval|data.rule.sg_tag|
|message|data.rule.sg_tag_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_SG_022.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_security_group', 'aws_security_group_rule']


[securitygroup.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/securitygroup.rego
