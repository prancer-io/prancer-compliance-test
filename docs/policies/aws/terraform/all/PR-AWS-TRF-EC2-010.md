



# Title: Ensure EBS volumes are encrypted using Customer Managed Key (CMK)


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-EC2-010

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ec2.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-EC2-010|
|eval|data.rule.ebs_volume_kms|
|message|data.rule.ebs_volume_kms_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#kms_key_id' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_EC2_010.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This control checks if the default AWS Key is used for encryption. GS mandates CMK to be used for encryption.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'AWS Well-Architected Framework-Identity and Access Management', 'LGPD', 'CSA CCM', "CyberSecurity Law of the People's Republic of China", 'CMMC', 'GDPR', 'HITRUST', 'MAS TRM', 'MITRE ATT&CK', 'MLPS', 'NIST 800', 'NIST CSF', 'RMiT', 'SOC 2']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_instance']


[ec2.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ec2.rego
