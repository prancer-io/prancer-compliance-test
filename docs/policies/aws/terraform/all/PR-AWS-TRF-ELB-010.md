



# Title: AWS Elastic Load Balancer with listener TLS/SSL disabled


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ELB-010

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([elb.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ELB-010|
|eval|data.rule.elb_listener_ssl|
|message|data.rule.elb_listener_ssl_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elb' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ELB_010.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies Elastic Load Balancers which have listener TLS/SSL disabled. As Load Balancers will be handling all incoming requests and routing the traffic accordingly; The listeners on the load balancers should always receive traffic over secure channel with a valid SSL certificate configured.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CMMC', 'CSA CCM', 'CSA CCM v3.0.1-DSI-03', 'CSA CCM v3.0.1-EKM-03', 'CSA CCM v3.0.1-IPY-04', 'CSA CCM v3.0.1-IVS-10', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 21", "CyberSecurity Law of the People's Republic of China-Article 40", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.185', 'GDPR', 'GDPR-Article 46', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:05.i', 'HITRUST CSF v9.3-Control Reference:09.m', 'HITRUST CSF v9.3-Control Reference:09.x', 'HITRUST v.9.4.2-Control Reference:09.s', 'ISO 27001', 'ISO 27001:2013-A.13.1.1', 'ISO 27001:2013-A.14.1.3', 'ISO 27001:2013-A.6.2.2', 'ISO 27001:2013-A.8.2.3', 'LGPD', 'MAS TRM', 'MAS TRM 2021-11.1.1', 'MAS TRM 2021-14.1.2', 'MLPS', 'MLPS 2.0-8.1.2.2', 'NIST 800', 'NIST 800-171 Rev1-3.13.8', 'NIST 800-53 Rev 5-Transmission Confidentiality and Integrity \| Cryptographic Protection', 'NIST 800-53 Rev4-SC-8 (1)', 'NIST CSF', 'NIST CSF-PR.DS-2', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.8', 'NIST SP 800-172-3.1.3e', 'PCI DSS v3.2.1-2.3', 'PCI DSS v3.2.1-4.1', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.1.4', 'RMiT', 'Risk Management in Technology (RMiT)-10.68', 'SOC 2', 'SOC 2-CC6.7']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_elb']


[elb.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/elb.rego
