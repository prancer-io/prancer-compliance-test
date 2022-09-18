



# Title: Ensure Redshift is not deployed outside of a VPC


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-RSH-006

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([redshift.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-RSH-006|
|eval|data.rule.redshift_deploy_vpc|
|message|data.rule.redshift_deploy_vpc_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_RSH_006.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure that your Redshift clusters are provisioned within the AWS EC2-VPC platform instead of EC2-Classic platform (outdated) for better flexibility and control over clusters security, traffic routing, availability and more.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'HIPAA', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_redshift_cluster']


[redshift.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/redshift.rego
