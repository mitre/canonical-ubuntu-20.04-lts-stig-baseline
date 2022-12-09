control 'SV-238299' do
  title 'The Ubuntu operating system must initiate session audits at system start-up. '
  desc "If auditing is enabled late in the start-up process, the actions of some start-up processes
may not be audited. Some audit systems also maintain state information only available if
auditing is enabled before a given process is created. "
  desc 'check', "Verify that the Ubuntu operating system enables auditing at system startup.

Verify that
the auditing is enabled in grub with the following command:

$ sudo grep \"^\\s*linux\"
/boot/grub/grub.cfg

linux        /boot/vmlinuz-5.4.0-31-generic
root=UUID=74d13bcd-6ebd-4493-b5d2-3ebc37d01702 ro  audit=1
linux
/boot/vmlinuz-5.4.0-31-generic root=UUID=74d13bcd-6ebd-4493-b5d2-3ebc37d01702 ro
recovery nomodeset audit=1

If any linux lines do not contain \"audit=1\", this is a finding. "
  desc 'fix', "Configure the Ubuntu operating system to produce audit records at system startup.

Edit the
\"/etc/default/grub\" file and add \"audit=1\" to the \"GRUB_CMDLINE_LINUX\" option.

To
update the grub config file, run:

$ sudo update-grub "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000254-GPOS-00095 '
  tag gid: 'V-238299 '
  tag rid: 'SV-238299r654072_rule '
  tag stig_id: 'UBTU-20-010198 '
  tag fix_id: 'F-41468r654071_fix '
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    grub_entries = command('grep "^\s*linux" /boot/grub/grub.cfg').stdout.strip.split("\n").entries

    grub_entries.each do |entry|
      describe entry do
        it { should include 'audit=1' }
      end
    end
  end
end
