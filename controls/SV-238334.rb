control 'SV-238334' do
  title "The Ubuntu operating system must disable kernel core dumps  so that it can fail to a secure state
if system initialization fails, shutdown fails or aborts fail. "
  desc "Kernel core dumps may contain the full contents of system memory at the time of the crash.
Kernel core dumps may consume a considerable amount of disk space and may result in denial of
service by exhausting the available space on the target file system partition. "
  desc 'check', "Verify that kernel core dumps are disabled unless needed.

Check if \"kdump\" service is
active with the following command:

$ systemctl is-active kdump.service
inactive

If
the \"kdump\" service is active, ask the SA if the use of the service is required and documented
with the ISSO.

If the service is active and is not documented, this is a finding. "
  desc 'fix', "If kernel core dumps are not required, disable the \"kdump\" service with the following
command:

$ sudo systemctl disable kdump.service

If kernel core dumps are required,
document the need with the ISSO. "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000184-GPOS-00078 '
  tag gid: 'V-238334 '
  tag rid: 'SV-238334r654177_rule '
  tag stig_id: 'UBTU-20-010413 '
  tag fix_id: 'F-41503r654176_fix '
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
  tag 'host', 'container'

  is_kdump_required = input('is_kdump_required')
  if is_kdump_required
    describe service('kdump') do
      it { should be_enabled }
      it { should be_installed }
      it { should be_running }
    end
  else
    describe service('kdump') do
      it { should_not be_enabled }
      it { should_not be_installed }
      it { should_not be_running }
    end
  end
end
