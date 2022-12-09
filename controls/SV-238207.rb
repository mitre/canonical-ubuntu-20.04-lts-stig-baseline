control 'SV-238207' do
  title "The Ubuntu operating system must automatically terminate a user session after inactivity
timeouts have expired. "
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

This capability is typically reserved for specific operating
system functionality where the system owner, data owner, or organization requires
additional assurance. "
  desc 'check', "Verify the operating system automatically terminates a user session after inactivity
timeouts have expired.

Check that \"TMOUT\" environment variable is set in the
\"/etc/bash.bashrc\" file or in any file inside the \"/etc/profile.d/\" directory by
performing the following command:

$ grep -E \"\\bTMOUT=[0-9]+\" /etc/bash.bashrc
/etc/profile.d/*

TMOUT=600

If \"TMOUT\" is not set, or if the value is \"0\" or is commented
out, this is a finding. "
  desc 'fix', "Configure the operating system to automatically terminate a user session after inactivity
timeouts have expired or at shutdown.

Create the file
\"/etc/profile.d/99-terminal_tmout.sh\" file if it does not exist.

Modify or append the
following line in the \"/etc/profile.d/99-terminal_tmout.sh \" file:

TMOUT=600

This
will set a timeout value of 10 minutes for all future sessions.

To set the timeout for the
current sessions, execute the following command over the terminal session:

$ export
TMOUT=600 "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000279-GPOS-00109 '
  tag gid: 'V-238207 '
  tag rid: 'SV-238207r853404_rule '
  tag stig_id: 'UBTU-20-010013 '
  tag fix_id: 'F-41376r653795_fix '
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
  tag 'host', 'container'

  profile_files = command('find /etc/profile.d/ /etc/bash.bashrc -type f').stdout.strip.split("\n").entries
  timeout = input('tmout').to_s

  describe.one do
    profile_files.each do |pf|
      describe file(pf.strip) do
        its('content') { should match "^TMOUT=#{timeout}$" }
      end
    end
  end
end
