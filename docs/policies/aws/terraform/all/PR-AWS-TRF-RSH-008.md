



# Title: Ensure AWS Redshift - Enhanced VPC routing must be enabled.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-RSH-008

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([redshift.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-RSH-008|
|eval|data.rule.redshift_enhanced_vpc_routing|
|message|data.rule.redshift_enhanced_vpc_routing_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_RSH_008.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It is to check enhanced VPC routing is enabled or not forces all COPY and UNLOAD traffic between your cluster and your data repositories through your virtual private cloud (VPC) based on the Amazon VPC service.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI DSS', 'HIPAA', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_redshift_cluster']


[redshift.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/redshift.rego
