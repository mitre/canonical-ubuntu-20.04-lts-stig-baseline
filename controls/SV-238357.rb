control 'SV-238357' do
  title "The Ubuntu operating system must synchronize internal information system clocks to the
authoritative time source when the time difference is greater than one second. "
  desc "Inaccurate time stamps make it more difficult to correlate events and can lead to an
inaccurate analysis. Determining the correct time a particular event occurred on a system is
critical when conducting forensic analysis and investigating system events.


Synchronizing internal information system clocks provides uniformity of time stamps for
information systems with multiple system clocks and systems connected over a network.
Organizations should consider setting time periods for different types of systems (e.g.,
financial, legal, or mission-critical systems).

Organizations should also consider
endpoints that may not have regular access to the authoritative time server (e.g., mobile,
teleworking, and tactical endpoints). This requirement is related to the comparison done
every 24 hours in SRG-OS-000355 because a comparison must be done in order to determine the
time difference. "
  desc 'check', "Verify the operating system synchronizes internal system clocks to the authoritative time
source when the time difference is greater than one second.

Check the value of \"makestep\" by
running the following command:

$ sudo grep makestep /etc/chrony/chrony.conf

makestep
1 -1

If the makestep option is commented out or is not set to \"1 -1\", this is a finding. "
  desc 'fix', "Configure chrony to synchronize the internal system clocks to the authoritative source when
the time difference is greater than one second by doing the following:

Edit the
\"/etc/chrony/chrony.conf\" file and add:

makestep 1 -1

Restart the chrony service:

$
sudo systemctl restart chrony.service "
  impact 0.3
  tag severity: 'low '
  tag gtitle: 'SRG-OS-000356-GPOS-00144 '
  tag gid: 'V-238357 '
  tag rid: 'SV-238357r853432_rule '
  tag stig_id: 'UBTU-20-010436 '
  tag fix_id: 'F-41526r654245_fix '
  tag cci: ['CCI-002046']
  tag nist: ['AU-8 (1) (b)']
  tag 'host', 'container'

  chrony_file_path = input('chrony_config_file')
  chrony_file = file(chrony_file_path)

  if chrony_file.exist?
    describe chrony_file do
      subject { chrony_file }
      its('content') { should match(/^makestep 1 -1/) }
    end
  else
    describe(chrony_file_path + ' exists') do
      subject { chrony_file.exist? }
      it { should be true }
    end
  end
end
