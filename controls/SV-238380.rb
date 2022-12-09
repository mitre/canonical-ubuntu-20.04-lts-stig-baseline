control 'SV-238380' do
  title 'The Ubuntu operating system must disable the x86 Ctrl-Alt-Delete key sequence. '
  desc "A locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the
system. If accidentally pressed, as could happen in the case of a mixed OS environment, this
can create the risk of short-term loss of availability of systems due to unintentional
reboot. "
  desc 'check', "Verify the Ubuntu operating system is not configured to reboot the system when
Ctrl-Alt-Delete is pressed.

Check that the \"ctrl-alt-del.target\" (otherwise also known
as reboot.target) is not active with the following command:

$ sudo systemctl status
ctrl-alt-del.target
ctrl-alt-del.target
Loaded: masked (Reason: Unit
ctrl-alt-del.target is masked.)
Active: inactive (dead)

If the \"ctrl-alt-del.target\"
is not masked, this is a finding. "
  desc 'fix', "Configure the system to disable the Ctrl-Alt-Delete sequence for the command line with the
following commands:

$ sudo systemctl disable ctrl-alt-del.target

$ sudo systemctl
mask ctrl-alt-del.target

Reload the daemon to take effect:

$ sudo systemctl
daemon-reload "
  impact 0.7
  tag severity: 'high '
  tag gtitle: 'SRG-OS-000480-GPOS-00227 '
  tag gid: 'V-238380 '
  tag rid: 'SV-238380r832974_rule '
  tag stig_id: 'UBTU-20-010460 '
  tag fix_id: 'F-41549r832973_fix '
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host', 'container'

  describe service('ctrl-alt-del.target') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end
