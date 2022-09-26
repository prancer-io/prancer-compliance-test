



# Title: AWS Redshift clusters should not be publicly accessible


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-RSH-002

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([redshift.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-RSH-002|
|eval|data.rule.redshift_public|
|message|data.rule.redshift_public_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_RSH_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy identifies AWS Redshift clusters which are accessible publicly.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CSA-CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'NIST 800', 'SOC 2']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_redshift_cluster']


[redshift.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/redshift.rego
