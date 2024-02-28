control 'SV-238362' do
  title "The Ubuntu operating system must be configured such that Pluggable Authentication Module
(PAM) prohibits the use of cached authentications after one day. "
  desc "If cached authentication information is out-of-date, the validity of the authentication
information may be questionable. "
  desc 'check', "If smart card authentication is not being used on the system, this s Not Applicable.

Verify
that PAM prohibits the use of cached authentications after one day with the following
command:

$ sudo grep offline_credentials_expiration /etc/sssd/sssd.conf
/etc/sssd/conf.d/*.conf

offline_credentials_expiration = 1

If
\"offline_credentials_expiration\" is not set to a value of \"1\" in \"/etc/sssd/sssd.conf\" or
in a file with a name ending in .conf in the \"/etc/sssd/conf.d/\" directory, this is a finding. "
  desc 'fix', "Configure PAM to prohibit the use of cached authentications after one day. Add or change the
following line in \"/etc/sssd/sssd.conf\" just below the line \"[pam]\":


offline_credentials_expiration = 1

Note: It is valid for this configuration to be in a
file with a name that ends with \".conf\" and does not begin with a \".\" in the \"/etc/sssd/conf.d/\"
directory instead of the \"/etc/sssd/sssd.conf\" file. "
  impact 0.3
  tag severity: 'low '
  tag gtitle: 'SRG-OS-000383-GPOS-00166 '
  tag gid: 'V-238362 '
  tag rid: 'SV-238362r853437_rule '
  tag stig_id: 'UBTU-20-010441 '
  tag fix_id: 'F-41531r654260_fix '
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
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
    config_file = input('sssd_conf_path')
    config_file_exists = file(config_file).exist?

    if config_file_exists
      describe parse_config_file(config_file) do
        its('offline_credentials_expiration') { should cmp '1' }
      end
    else
      describe(config_file + ' exists') do
        subject { config_file_exists }
        it { should be true }
      end
    end
  end
end
