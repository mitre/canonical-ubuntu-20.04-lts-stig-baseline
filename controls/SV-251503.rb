control 'SV-251503' do
  title 'The Ubuntu operating system must not have accounts configured with blank or null passwords. '
  desc "If an account has an empty password, anyone could log on and run commands with the privileges of
that account. Accounts with empty passwords should never be used in operational
environments. "
  desc 'check', "Check the \"/etc/shadow\" file for blank passwords with the following command:

$ sudo awk -F:
'!$2 {print $1}' /etc/shadow

If the command returns any results, this is a finding. "
  desc 'fix', "Configure all accounts on the system to have a password or lock the account with the following
commands:

Perform a password reset:
$ sudo passwd [username]
Lock an account:
$ sudo
passwd -l [username] "
  impact 0.7
  tag severity: 'high '
  tag gtitle: 'SRG-OS-000480-GPOS-00227 '
  tag gid: 'V-251503 '
  tag rid: 'SV-251503r808506_rule '
  tag stig_id: 'UBTU-20-010462 '
  tag fix_id: 'F-54892r808505_fix '
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host', 'container'

  describe command("sudo awk -F: '!$2 {print $1}' /etc/shadow") do
    its('stdout') { should be_empty }
  end
end
