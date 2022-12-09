control 'SV-238200' do
  title "The Ubuntu operating system must allow users to directly initiate a session lock for all
connection types. "
  desc "A session lock is a temporary action taken when a user stops work and moves away from the
immediate physical vicinity of the information system but does not want to log out because of
the temporary nature of the absence.

The session lock is implemented at the point where
session activity can be determined. Rather than be forced to wait for a period of time to expire
before the user session can be locked, the Ubuntu operating systems need to provide users with
the ability to manually invoke a session lock so users may secure their session if they need to
temporarily vacate the immediate physical vicinity.

 "
  desc 'check', "Verify the Ubuntu operating system has the \"vlock\" package installed by running the
following command:

$ dpkg -l | grep vlock

If \"vlock\" is not installed, this is a finding. "
  desc 'fix', "Install the \"vlock\" package (if it is not already installed) by running the following
command:

$ sudo apt-get install vlock "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000030-GPOS-00011 '
  tag satisfies: %w(SRG-OS-000030-GPOS-00011 SRG-OS-000031-GPOS-00012)
  tag gid: 'V-238200 '
  tag rid: 'SV-238200r653775_rule '
  tag stig_id: 'UBTU-20-010005 '
  tag fix_id: 'F-41369r653774_fix '
  tag cci: %w(CCI-000058 CCI-000060)
  tag nist: ['AC-11 a', 'AC-11 (1)']
  tag 'host', 'container'

  describe package('vlock') do
    it { should be_installed }
  end
end
