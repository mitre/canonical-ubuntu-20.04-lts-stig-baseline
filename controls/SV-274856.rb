control 'SV-274856' do
  title 'Ubuntu 20.04 LTS must be configured such that Pluggable Authentication Module (PAM) prohibits the use of cached authentications after one day.'
  desc 'If cached authentication information is out of date, the validity of the authentication information may be questionable.'
  desc 'check', 'Note: If smart card authentication is not being used on the system, this is not applicable.

Verify that PAM prohibits the use of cached authentications after one day with the following command:

$ sudo grep offline_credentials_expiration /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf
offline_credentials_expiration = 1

If "offline_credentials_expiration" is not set to a value of "1" in "/etc/sssd/sssd.conf" or in a file with a name ending in .conf in the "/etc/sssd/conf.d/" directory, this is a finding.'
  desc 'fix', 'Configure PAM to prohibit the use of cached authentications after one day. Add or change the following line in "/etc/sssd/sssd.conf" just below the line "[pam]":

offline_credentials_expiration = 1

Note: It is valid for this configuration to be in a file with a name that ends with ".conf" and does not begin with a "." in the "/etc/sssd/conf.d/" directory instead of the "/etc/sssd/sssd.conf" file.'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000383-GPOS-00166'
  tag gid: 'V-274856'
  tag rid: 'SV-274856r1106132_rule'
  tag stig_id: 'UBTU-20-010021'
  tag fix_id: 'F-78862r1101688_fix'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
  tag 'host'

  sssd_config = parse_config_file('/etc/sssd/sssd.conf')

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('smart_card_enabled')
    impact 0.0
    describe 'The system is not utilizing smart card authentication' do
      skip 'The system is not utilizing smart card authentication, this control
      is Not Applicable.'
    end
  else
    describe.one do
      describe 'Cache credentials enabled' do
        subject { sssd_config.content }
        it { should_not match(/cache_credentials\s*=\s*true/) }
      end
      describe 'Offline credentials expiration' do
        subject { sssd_config }
        its('pam.offline_credentials_expiration') { should cmp '1' }
      end
    end
  end
end
