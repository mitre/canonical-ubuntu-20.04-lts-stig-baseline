control 'SV-238332' do
  title "The Ubuntu operating system must set a sticky bit  on all public directories to prevent
unauthorized and unintended information transferred via shared system resources. "
  desc "Preventing unauthorized information transfers mitigates the risk of information,
including encrypted representations of information, produced by the actions of prior
users/roles (or the actions of processes acting on behalf of prior users/roles) from being
available to any current users/roles (or current processes) that obtain access to shared
system resources (e.g., registers, main memory, hard disks) after those resources have been
released back to information systems. The control of information in shared resources is also
commonly referred to as object reuse and residual information protection.

This
requirement generally applies to the design of an information technology product, but it can
also apply to the configuration of particular information system components that are, or
use, such products. This can be verified by acceptance/validation processes in DoD or other
government agencies.

There may be shared resources with configurable protections (e.g.,
files in storage) that may be assessed on specific information system components. "
  desc 'check', "Verify that all public (world-writeable) directories have the public sticky bit set.

Find
world-writable directories that lack the sticky bit by running the following command:

$
sudo find / -type d -perm -002 ! -perm -1000

If any world-writable directories are found
missing the sticky bit, this is a finding. "
  desc 'fix', "Configure all public directories to have the sticky bit set to prevent unauthorized and
unintended information transferred via shared system resources.

Set the sticky bit on all
public directories using the following command, replacing \"[Public Directory]\" with any
directory path missing the sticky bit:

$ sudo chmod +t  [Public Directory] "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000138-GPOS-00069 '
  tag gid: 'V-238332 '
  tag rid: 'SV-238332r654171_rule '
  tag stig_id: 'UBTU-20-010411 '
  tag fix_id: 'F-41501r654170_fix '
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
  tag 'host', 'container'

  lines = command('find / -xdev -type d  \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null').stdout.strip.split("\n").entries
  if lines.count > 0
    lines.each do |line|
      dir = line.strip
      describe directory(dir) do
        it { should be_sticky }
      end
    end
  else
    describe 'Sticky bit has been set on all world writable directories' do
      subject { lines }
      its('count') { should eq 0 }
    end
  end
end
