control 'SV-238213' do
  title "The Ubuntu operating system must immediately terminate all network connections associated
with SSH traffic at the end of the session or after 10 minutes of inactivity. "
  desc "Terminating an idle session within a short time period reduces the window of opportunity for
unauthorized personnel to take control of a management session enabled on the console or
console port that has been left unattended. In addition, quickly terminating an idle session
will also free up resources committed by the managed network element.

Terminating network
connections associated with communications sessions includes, for example,
de-allocating associated TCP/IP address/port pairs at the operating system level, and
de-allocating networking assignments at the application level if multiple application
sessions are using a single operating system-level network connection. This does not mean
that the operating system terminates all sessions or network access; it only ends the
inactive session and releases the resources associated with that session. "
  desc 'check', "Verify that all network connections associated with SSH traffic are automatically
terminated at the end of the session or after 10 minutes of inactivity.

Verify the
\"ClientAliveInterval\" variable is set to a value of \"600\" or less by performing the following
command:

$ sudo grep -ir clientalive /etc/ssh/sshd_config*

ClientAliveInterval
600

If \"ClientAliveInterval\" does not exist, is not set to a value of \"600\" or less in
\"/etc/ssh/sshd_config\", or is commented out, this is a finding.
If conflicting results are
returned, this is a finding. "
  desc 'fix', "Configure the Ubuntu operating system to automatically terminate all network connections
associated with SSH traffic at the end of a session or after a 10-minute period of inactivity.


Modify or append the following line in the \"/etc/ssh/sshd_config\" file replacing
\"[Interval]\" with a value of \"600\" or less:

ClientAliveInterval 600

Restart the SSH
daemon for the changes to take effect:

$ sudo systemctl restart sshd.service "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000163-GPOS-00072 '
  tag gid: 'V-238213 '
  tag rid: 'SV-238213r858523_rule '
  tag stig_id: 'UBTU-20-010037 '
  tag fix_id: 'F-41382r653813_fix '
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
  tag 'host', 'container'

  describe sshd_config do
    its('ClientAliveInterval') { should cmp 600 }
  end
end
