control 'SV-238199' do
  title "The Ubuntu operating system must retain a user's session lock until that user reestablishes
access using established identification and authentication procedures. "
  desc "A session lock is a temporary action taken when a user stops work and moves away from the
immediate physical vicinity of the information system but does not want to log out because of
the temporary nature of the absence.

The session lock is implemented at the point where
session activity can be determined.

Regardless of where the session lock is determined and
implemented, once invoked, a session lock of the Ubuntu operating system must remain in place
until the user reauthenticates. No other activity aside from reauthentication must unlock
the system.

 "
  desc 'check', "Verify the Ubuntu operation system has a graphical user interface session lock enabled.


Note: If the Ubuntu operating system does not have a graphical user interface installed,
this requirement is Not Applicable.

Get the \"lock-enabled\" setting to verify the
graphical user interface session has the lock enabled with the following command:

$ sudo
gsettings get org.gnome.desktop.screensaver lock-enabled

 true

If \"lock-enabled\" is
not set to \"true\", this is a finding. "
  desc 'fix', "Configure the Ubuntu operating system to allow a user to lock the current graphical user
interface session.

Note: If the Ubuntu operating system does not have a graphical user
interface installed, this requirement is Not Applicable.

Set the \"lock-enabled\" setting
to allow graphical user interface session locks with the following command:

$ sudo
gsettings set org.gnome.desktop.screensaver lock-enabled true "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000028-GPOS-00009 '
  tag satisfies: %w(SRG-OS-000028-GPOS-00009 SRG-OS-000029-GPOS-00010)
  tag gid: 'V-238199 '
  tag rid: 'SV-238199r653772_rule '
  tag stig_id: 'UBTU-20-010004 '
  tag fix_id: 'F-41368r653771_fix '
  tag cci: %w(CCI-000056 CCI-000057)
  tag nist: ['AC-11 b', 'AC-11 a']
  tag 'host', 'container'

  xorg_status = command('which Xorg').exit_status

  if xorg_status == 0
    describe command('gsettings get org.gnome.desktop.screensaver lock-enabled').stdout.strip do
      it { should cmp true }
    end
  else
    describe command('which Xorg').exit_status do
      skip("GUI not installed.\nwhich Xorg exit_status: " + command('which Xorg').exit_status.to_s)
    end
  end
end
