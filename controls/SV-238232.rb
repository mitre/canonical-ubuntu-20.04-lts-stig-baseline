control 'SV-238232' do
  title "The Ubuntu operating system must electronically verify Personal Identity Verification
(PIV) credentials. "
  desc "The use of PIV credentials facilitates standardization and reduces the risk of unauthorized
access.

DoD has mandated the use of the CAC to support identity management and personal
authentication for systems covered under Homeland Security Presidential Directive (HSPD)
12, as well as making the CAC a primary component of layered protection for national security
systems. "
  desc 'check', "Verify the Ubuntu operating system electronically verifies PIV credentials.

Verify that
certificate status checking for multifactor authentication is implemented with the
following command:

$ sudo grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf |
awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy |
grep ocsp_on

cert_policy = ca,signature,ocsp_on;

If \"cert_policy\" is not set to
\"ocsp_on\", or the line is commented out, this is a finding. "
  desc 'fix', "Configure the Ubuntu operating system to do certificate status checking for multifactor
authentication.

Modify all of the \"cert_policy\" lines in
\"/etc/pam_pkcs11/pam_pkcs11.conf\" to include \"ocsp_on\". "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000377-GPOS-00162 '
  tag gid: 'V-238232 '
  tag rid: 'SV-238232r853412_rule '
  tag stig_id: 'UBTU-20-010065 '
  tag fix_id: 'F-41401r653870_fix '
  tag cci: ['CCI-001954']
  tag nist: ['IA-2 (12)']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    config_file_exists = file('/etc/pam_pkcs11/pam_pkcs11.conf').exist?
    if config_file_exists
      describe parse_config_file('/etc/pam_pkcs11/pam_pkcs11.conf') do
        its('cert_policy') { should include 'ocsp_on' }
      end
    else
      describe '/etc/pam_pkcs11/pam_pkcs11.conf exists' do
        subject { config_file_exists }
        it { should be true }
      end
    end
  end
end
