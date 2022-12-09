control 'SV-238321' do
  title "The Ubuntu operating system must have a crontab script running weekly to offload audit events
of standalone systems. "
  desc "Information stored in one location is vulnerable to accidental or incidental deletion or
alteration.

Offloading is a common process in information systems with limited audit
storage capacity. "
  desc 'check', "Note: If this is an interconnected system, this is Not Applicable.

Verify there is a script
that offloads audit data and that script runs weekly.

Check if there is a script in the
\"/etc/cron.weekly\" directory that offloads audit data:

# sudo ls /etc/cron.weekly


audit-offload

Check if the script inside the file does offloading of audit logs to
external media.

If the script file does not exist or does not offload audit logs, this is a
finding. "
  desc 'fix', "Create a script that offloads audit logs to external media and runs weekly.

The script must
be located in the \"/etc/cron.weekly\" directory. "
  impact 0.3
  tag severity: 'low '
  tag gtitle: 'SRG-OS-000479-GPOS-00224 '
  tag gid: 'V-238321 '
  tag rid: 'SV-238321r853428_rule '
  tag stig_id: 'UBTU-20-010300 '
  tag fix_id: 'F-41490r654137_fix '
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
  tag 'host', 'container'

  cron_file = input('auditoffload_config_file')
  cron_file_exists = file(cron_file).exist?

  if cron_file_exists
    describe file(cron_file) do
      its('content') { should_not be_empty }
    end
  else
    describe cron_file + ' exists' do
      subject { cron_file_exists }
      it { should be true }
    end
  end
end
