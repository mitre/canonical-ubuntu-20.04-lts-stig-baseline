control 'SV-251504' do
  title 'The Ubuntu operating system must not allow accounts configured with blank or null passwords. '
  desc "If an account has an empty password, anyone could log on and run commands with the privileges of
that account. Accounts with empty passwords should never be used in operational
environments. "
  desc 'check', "To verify that null passwords cannot be used, run the following command:

$ grep nullok
/etc/pam.d/common-password

If this produces any output, it may be possible to log on with
accounts with empty passwords.

If null passwords can be used, this is a finding. "
  desc 'fix', "If an account is configured for password authentication but does not have an assigned
password, it may be possible to log on to the account without authenticating.

Remove any
instances of the \"nullok\" option in \"/etc/pam.d/common-password\" to prevent logons with
empty passwords. "
  impact 0.7
  tag severity: 'high '
  tag gtitle: 'SRG-OS-000480-GPOS-00227 '
  tag gid: 'V-251504 '
  tag rid: 'SV-251504r832977_rule '
  tag stig_id: 'UBTU-20-010463 '
  tag fix_id: 'F-54893r832976_fix '
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    describe command('grep nullok /etc/pam.d/common-password') do
      its('stdout') { should be_empty }
    end
  end
end
