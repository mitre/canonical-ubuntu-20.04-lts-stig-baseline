control 'SV-238212' do
  title "The Ubuntu operating system must immediately terminate all network connections associated
with SSH traffic after a period of inactivity. "
  desc "Automatic session termination addresses the termination of user-initiated logical
sessions in contrast to the termination of network connections that are associated with
communications sessions (i.e., network disconnect). A logical session (for local,
network, and remote access) is initiated whenever a user (or process acting on behalf of a
user) accesses an organizational information system. Such user sessions can be terminated
(and thus terminate user access) without terminating network sessions.

Session
termination terminates all processes associated with a user's logical session except those
processes that are specifically created by the user (i.e., session owner) to continue after
the session is terminated.

Conditions or trigger events requiring automatic session
termination can include, for example, organization-defined periods of user inactivity,
targeted responses to certain types of incidents, and time-of-day restrictions on
information system use.

This capability is typically reserved for specific Ubuntu
operating system functionality where the system owner, data owner, or organization
requires additional assurance. "
  desc 'check', "Verify that all network connections associated with SSH traffic automatically terminate
after a period of inactivity.

Verify the \"ClientAliveCountMax\" variable is set in the
\"/etc/ssh/sshd_config\" file by performing the following command:

$ sudo grep -ir
clientalivecountmax /etc/ssh/sshd_config*

ClientAliveCountMax  1

If
\"ClientAliveCountMax\" is not set, is not set to \"1\", or is commented out, this is a finding.
If
conflicting results are returned, this is a finding. "
  desc 'fix', "Configure the Ubuntu operating system to automatically terminate inactive SSH sessions
after a period of inactivity.

Modify or append the following line in the
\"/etc/ssh/sshd_config\" file, replacing \"[Count]\" with a value of 1:


ClientAliveCountMax 1

Restart the SSH daemon for the changes to take effect:

$ sudo
systemctl restart sshd.service "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000126-GPOS-00066 '
  tag gid: 'V-238212 '
  tag rid: 'SV-238212r858521_rule '
  tag stig_id: 'UBTU-20-010036 '
  tag fix_id: 'F-41381r653810_fix '
  tag cci: ['CCI-000879']
  tag nist: ['MA-4 e']
  tag 'host', 'container'

  describe sshd_config do
    its('ClientAliveCountMax') { should cmp 1 }
  end
end
