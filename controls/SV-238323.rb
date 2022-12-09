control 'SV-238323' do
  title "The Ubuntu operating system must limit the number of concurrent sessions to ten for all
accounts and/or account types. "
  desc "The Ubuntu operating system management includes the ability to control the number of users
and user sessions that utilize an operating system. Limiting the number of allowed users and
sessions per user is helpful in reducing the risks related to DoS attacks.

This requirement
addresses concurrent sessions for information system accounts and does not address
concurrent sessions by single users via multiple system accounts. The maximum number of
concurrent sessions should be defined based upon mission needs and the operational
environment for each system. "
  desc 'check', "Verify the Ubuntu operating system limits the number of concurrent sessions to 10 for all
accounts and/or account types by running the following command:

$ grep maxlogins
/etc/security/limits.conf | grep -v '^* hard maxlogins'

The result must contain the
following line:

* hard maxlogins 10

If the \"maxlogins\" item is missing or the value is not
set to 10 or less or is commented out, this is a finding. "
  desc 'fix', "Configure the Ubuntu operating system to limit the number of concurrent sessions to 10 for all
accounts and/or account types.

Add the following line to the top of the
\"/etc/security/limits.conf\" file:

* hard maxlogins 10 "
  impact 0.3
  tag severity: 'low '
  tag gtitle: 'SRG-OS-000027-GPOS-00008 '
  tag gid: 'V-238323 '
  tag rid: 'SV-238323r654144_rule '
  tag stig_id: 'UBTU-20-010400 '
  tag fix_id: 'F-41492r654143_fix '
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
  tag 'host', 'container'

  describe limits_conf do
    its('*') { should include ['hard', 'maxlogins', input('maxlogins').to_s] }
  end
end
