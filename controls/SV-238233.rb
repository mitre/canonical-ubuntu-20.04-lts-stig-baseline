control 'SV-238233' do
  title "The Ubuntu operating system for PKI-based authentication, must implement a local cache of
revocation data in case of the inability to access revocation information via the network. "
  desc "Without configuring a local cache of revocation data, there is the potential to allow access
to users who are no longer authorized (users with revoked certificates). "
  desc 'check', "Verify the Ubuntu operating system, for PKI-based authentication, uses local revocation
data when unable to access it from the network.

Verify that \"crl_offline\" or \"crl_auto\" is
part of the \"cert_policy\" definition in \"/etc/pam_pkcs11/pam_pkcs11.conf\" using the
following command:

# sudo grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf | grep  -E --
'crl_auto|crl_offline'

cert_policy = ca,signature,ocsp_on,crl_auto;

If
\"cert_policy\" is not set to include \"crl_auto\" or \"crl_offline\", this is a finding. "
  desc 'fix', "Configure the Ubuntu operating system, for PKI-based authentication, to use local
revocation data when unable to access the network to obtain it remotely.

Add or update the
\"cert_policy\" option in \"/etc/pam/_pkcs11/pam_pkcs11.conf\" to include \"crl_auto\" or
\"crl_offline\".

cert_policy = ca,signature,ocsp_on, crl_auto;

If the system is
missing an \"/etc/pam_pkcs11/\" directory and an \"/etc/pam_pkcs11/pam_pkcs11.conf\", find
an example to copy into place and modify accordingly at
\"/usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example.gz\". "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000384-GPOS-00167 '
  tag gid: 'V-238233 '
  tag rid: 'SV-238233r853413_rule '
  tag stig_id: 'UBTU-20-010066 '
  tag fix_id: 'F-41402r653873_fix '
  tag cci: ['CCI-001991']
  tag nist: ['IA-5 (2) (d)']
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
    config_file_exists = file('/etc/pam_pkcs11/pam_pkcs11.conf').exist?
    if config_file_exists
      describe.one do
        describe parse_config_file('/etc/pam_pkcs11/pam_pkcs11.conf') do
          its('cert_policy') { should include 'crl_auto' }
        end
        describe parse_config_file('/etc/pam_pkcs11/pam_pkcs11.conf') do
          its('cert_policy') { should include 'crl_offline' }
        end
      end
    else
      describe '/etc/pam_pkcs11/pam_pkcs11.conf exists' do
        subject { config_file_exists }
        it { should be true }
      end
    end
  end
end
