control 'SV-238363' do
  title 'The Ubuntu operating system must implement NIST FIPS-validated cryptography to protect classified information and for the following: To provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', 'Verify the system is configured to run in FIPS mode with the following command:

$ grep -i 1 /proc/sys/crypto/fips_enabled
1

If a value of "1" is not returned, this is a finding.'
  desc 'fix', 'Configure the system to run in FIPS mode. Add "fips=1" to the kernel parameter during the Ubuntu operating systems install.

Enabling a FIPS mode on a pre-existing system involves a number of modifications to the Ubuntu operating system. Refer to the Ubuntu Server 20.04 FIPS 140-2 security policy document for instructions.

A subscription to the "Ubuntu Pro" plan is required to obtain the FIPS Kernel cryptographic modules and enable FIPS.'
  impact 0.7
  tag check_id: 'C-41573r654262_chk'
  tag severity: 'high'
  tag gid: 'V-238363'
  tag rid: 'SV-238363r1014774_rule'
  tag stig_id: 'UBTU-20-010442'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-41532r1014773_fix'
  tag satisfies: ['SRG-OS-000396-GPOS-00176', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000478-GPOS-00223']
  tag 'documentable'
  tag cci: ['CCI-002450', 'CCI-002890', 'CCI-003123']
  tag nist: ['SC-13 b', 'MA-4 (6)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe command('grep -i 1 /proc/sys/crypto/fips_enabled') do
    its('stdout') { should match('1') }
  end
end
