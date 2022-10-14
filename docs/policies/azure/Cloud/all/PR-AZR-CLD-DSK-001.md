



# Title: Azure disk should have Azure Disk Encryption (ADE) enabled


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-DSK-001

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_277']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([disks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-DSK-001|
|eval|data.rule.disk_encrypt|
|message|data.rule.disk_encrypt_err|
|remediationDescription|1. Attach the disk to the VM:<br>az vm disk attach --disk --new --resource-group --size-gb 128 --sku --vm-name<br><br>2. Enable encryption on the VM data disk:<br>az vm encryption enable --resource-group --vm-name --disk-encryption-keyvault --volume-type<br><br>References:<br><a href='https://docs.microsoft.com/en-us/cli/azure/vm/disk?view=azure-cli-latest#az-vm-disk-attach' target='_blank'>1. https://docs.microsoft.com/en-us/cli/azure/vm/disk?view=azure-cli-latest#az-vm-disk-attach</a><a href='https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-windows#enable-encryption-on-a-newly-added-disk-with-azure-cli' target='_blank'>2. https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-windows#enable-encryption-on-a-newly-added-disk-with-azure-cli</a>|
|remediationFunction|PR_AZR_CLD_DSK_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** To meet your organizational security or compliance requirement, Azure provides disk encryption at rest using Azure Storage Service Encryption (SSE) and Azure Disk Encryption (ADE). Starting February 2017, SSE is enabled by default for all managed disks. ADE is integrated with Azure Key Vault to help you control, manage, and audit the disk encryption keys and secrets.<br><br>This policy detects Virtual Machine (VM) OS disks that are not encrypted at rest using ADE. As a best practice, enable ADE for provide volume encryption for the OS disk. For more information, see https://docs.microsoft.com/en-us/azure/security/azure-security-disk-encryption-overview.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Azure Security Benchmark', 'Azure Security Benchmark (v2)-DP-5', 'Azure Security Benchmark (v3)-DP-4', 'Azure Security Benchmark (v3)-DP-5', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CIS', 'CIS v1.1 (Azure)-7.1', 'CIS v1.2.0 (Azure)-7.2', 'CIS v1.3.0 (Azure)-7.2', 'CIS v1.3.1 (Azure)-7.2', 'CIS v1.4.0 (Azure)-7.2', 'CSA CCM', 'CSA CCM v.4.0.1-CEK-03', 'CSA CCM v.4.0.1-DSP-10', 'CSA CCM v.4.0.1-UEM-11', "CyberSecurity Law of the People's Republic of China-Article 30", "CyberSecurity Law of the People's Republic of China-Article 31", "CyberSecurity Law of the People's Republic of China-Article 40", 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-CM.2.061', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:06.d', 'HITRUST v.9.4.2-Control Reference:09.s', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-10.1.1', 'ISO/IEC 27002:2013-12.2.1', 'ISO/IEC 27002:2013-12.3.1', 'ISO/IEC 27002:2013-13.2.1', 'ISO/IEC 27002:2013-13.2.3', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.1.3', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-8.3.1', 'ISO/IEC 27002:2013-8.3.3', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-10.1.1', 'ISO/IEC 27017:2015-10.1.2', 'ISO/IEC 27017:2015-6.1.1', 'ISO/IEC 27018:2019', 'ISO/IEC 27018:2019-10.1.2', 'ISO/IEC 27018:2019-12.3.1', 'NIST 800', 'NIST 800-53 Rev 5-Protection of Information at Rest', 'NIST 800-53 Rev 5-Remote Access \| Protection of Confidentiality and Integrity Using Encryption', 'NIST 800-53 Rev4-AC-17 (2)', 'NIST 800-53 Rev4-SC-28', 'NIST CSF', 'NIST CSF-PR.DS-1', 'NIST CSF-PR.DS-5', 'NIST SP', 'NIST SP 800-171 Revision 2-3.13.16', 'NIST SP 800-172-3.1.3e', 'PCI DSS', 'PCI DSS v3.2.1-3.4.1', 'PCI DSS v3.2.1-4.1', 'PIPEDA', 'PIPEDA-4.7.3']|
|service|['Compute']|



[disks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/disks.rego
