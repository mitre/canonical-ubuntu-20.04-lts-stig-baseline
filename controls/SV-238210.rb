control 'SV-238210' do
  title "The Ubuntu operating system must implement smart card logins for multifactor
authentication for local and network access to privileged and non-privileged accounts. "
  desc "Without the use of multifactor authentication, the ease of access to privileged functions is
greatly increased.

Multifactor authentication requires using two or more factors to
achieve authentication.

Factors include:
1) something a user knows (e.g.,
password/PIN);
2) something a user has (e.g., cryptographic identification device,
token); and
3) something a user is (e.g., biometric).

A privileged account is defined as an
information system account with authorizations of a privileged user.

Network access is
defined as access to an information system by a user (or a process acting on behalf of a user)
communicating through a network (e.g., local area network, wide area network, or the
internet).

The DoD CAC with DoD-approved PKI is an example of multifactor
authentication.

 "
  desc 'check', "Verify the Ubuntu operating system has the packages required for multifactor
authentication installed with the following commands:

$ dpkg -l | grep libpam-pkcs11

ii
libpam-pkcs11    0.6.8-4    amd64    Fully featured PAM module for using PKCS#11 smart cards

If the
\"libpam-pkcs11\" package is not installed, this is a finding.

Verify the sshd daemon allows
public key authentication with the following command:

$ grep -r ^Pubkeyauthentication
/etc/ssh/sshd_config*

PubkeyAuthentication yes

If this option is set to \"no\" or is
missing, this is a finding.
If conflicting results are returned, this is a finding. "
  desc 'fix', "Configure the Ubuntu operating system to use multifactor authentication for network access
to accounts.

Add or update \"pam_pkcs11.so\" in \"/etc/pam.d/common-auth\" to match the
following line:

auth    [success=2 default=ignore] pam_pkcs11.so

Set the sshd option
\"PubkeyAuthentication yes\" in the \"/etc/ssh/sshd_config\" file. "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000105-GPOS-00052 '
  tag satisfies: %w(SRG-OS-000105-GPOS-00052 SRG-OS-000106-GPOS-00053 SRG-OS-000107-GPOS-00054 SRG-OS-000108-GPOS-00055)
  tag gid: 'V-238210 '
  tag rid: 'SV-238210r858517_rule '
  tag stig_id: 'UBTU-20-010033 '
  tag fix_id: 'F-41379r653804_fix '
  tag cci: %w(CCI-000765 CCI-000766 CCI-000767 CCI-000768)
  tag nist: ['IA-2 (1)', 'IA-2 (2)', 'IA-2 (3)', 'IA-2 (4)']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  elsif input('pki_disabled')
    impact 0.0
    describe 'This system is not using PKI for authentication so the controls is Not Applicable.' do
      skip 'This system is not using PKI for authentication so the controls is Not Applicable.'
    end
  else
    describe package('libpam-pkcs11') do
      it { should be_installed }
    end

    describe sshd_config do
      its('PubkeyAuthentication') { should cmp 'yes' }
    end
  end
end
