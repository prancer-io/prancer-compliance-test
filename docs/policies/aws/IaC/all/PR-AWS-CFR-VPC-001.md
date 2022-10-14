



# Title: AWS VPC subnets should not allow automatic public IP assignment


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-VPC-001

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([vpc.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-VPC-001|
|eval|data.rule.vpc_subnet_autoip|
|message|data.rule.vpc_subnet_autoip_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-subnet.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_VPC_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies VPC subnets which allow automatic public IP assignment. VPC subnet is a part of the VPC having its own rules for traffic. Assigning the Public IP to the subnet automatically (on launch) can accidentally expose the instances within this subnet to internet and should be edited to 'No' post creation of the Subnet.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 26', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CMMC', 'CSA CCM', 'CSA CCM v3.0.1-DSI-02', 'CSA CCM v3.0.1-IAM-07', 'CSA CCM v3.0.1-IVS-06', 'CSA CCM v3.0.1-IVS-08', 'CSA CCM v3.0.1-MOS-06', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 21", "CyberSecurity Law of the People's Republic of China-Article 25", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AC.1.004', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.183', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SI.2.216', 'GDPR', 'GDPR-Article 25', 'GDPR-Article 46', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:01.n', 'HITRUST v.9.4.2-Control Reference:01.c', 'HITRUST v.9.4.2-Control Reference:09.m', 'ISO 27001', 'ISO 27001:2013-A.13.1.3', 'ISO 27001:2013-A.14.1.2', 'ISO 27001:2013-A.6.2.2', 'LGPD', 'MAS TRM', 'MAS TRM 2021-7.2.1', 'MAS TRM 2021-7.2.2', 'MLPS', 'MLPS 2.0-8.1.3.1', 'NIST 800', 'NIST 800-171 Rev1-3.13.1', 'NIST 800-171 Rev1-3.13.2', 'NIST 800-171 Rev1-3.13.5', 'NIST 800-53 Rev 5-Boundary Protection \| Connections to Public Networks', 'NIST 800-53 Rev 5-Boundary Protection \| Separate Subnets for Connecting to Different Security Domains', 'NIST 800-53 Rev4-CA-3 (4)', 'NIST 800-53 Rev4-SC-7 (22)', 'NIST CSF', 'NIST CSF-DE.AE-1', 'NIST CSF-DE.CM-1', 'NIST CSF-ID.RA-5', 'NIST CSF-PR.AC-5', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.5', 'NIST SP 800-172-3.14.3e', 'PCI DSS v3.2.1-1.3', 'PCI DSS v3.2.1-7.1', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.7.3', 'SOC 2', 'SOC 2-CC6.1', 'SOC 2-CC6.6', 'SOC 2-CC6.7']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::ec2::subnet']


[vpc.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/vpc.rego
