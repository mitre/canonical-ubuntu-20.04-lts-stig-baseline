control 'SV-238201' do
  title "The Ubuntu operating system must map the authenticated identity to the user or group account
for PKI-based authentication. "
  desc "Without mapping the certificate used to authenticate to the user account, the ability to
determine the identity of the individual user or group will not be available for forensic
analysis. "
  desc 'check', "Verify that \"use_mappers\" is set to \"pwent\" in \"/etc/pam_pkcs11/pam_pkcs11.conf\" file:


$ grep use_mappers /etc/pam_pkcs11/pam_pkcs11.conf
use_mappers = pwent

If
\"use_mappers\" is not found or the list does not contain \"pwent\" this is a finding. "
  desc 'fix', "Set \"use_mappers=pwent\" in \"/etc/pam_pkcs11/pam_pkcs11.conf\" or, if there is already a
comma-separated list of mappers, add it to the list, separated by comma, and before the null
mapper.

If the system is missing an \"/etc/pam_pkcs11/\" directory and an
\"/etc/pam_pkcs11/pam_pkcs11.conf\", find an example to copy into place and modify
accordingly at
\"/usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example.gz\". "
  impact 0.7
  tag severity: 'high '
  tag gtitle: 'SRG-OS-000068-GPOS-00036 '
  tag gid: 'V-238201 '
  tag rid: 'SV-238201r832933_rule '
  tag stig_id: 'UBTU-20-010006 '
  tag fix_id: 'F-41370r653777_fix '
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'This control is Not Applicable inside a container' do
      skip 'This control is Not Applicable inside a container'
    end
  elsif input('pki_disabled')
    impact 0.0
    describe 'This system is not using PKI for authentication so the controls is Not Applicable.' do
      skip 'This system is not using PKI for authentication so the controls is Not Applicable.'
    end
  else
    config_file = '/etc/pam_pkcs11/pam_pkcs11.conf'
    config_file_exists = file(config_file).exist?

    if config_file_exists
      describe parse_config_file(config_file) do
        its('use_mappers') { should cmp 'pwent' }
      end
    else
      describe(config_file + ' exists') do
        subject { config_file_exists }
        it { should be true }
      end
    end
  end
end
