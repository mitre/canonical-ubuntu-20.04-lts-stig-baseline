control 'SV-238244' do
  title "The Ubuntu operating system must shut down by default upon audit failure (unless
availability is an overriding concern). "
  desc "It is critical that when the operating system is at risk of failing to process audit logs as
required, it takes action to mitigate the failure. Audit processing failures include:
software/hardware errors; failures in the audit capturing mechanisms; and audit storage
capacity being reached or exceeded. Responses to audit failure depend upon the nature of the
failure mode.

When availability is an overriding concern, other approved actions in
response to an audit failure are as follows:

1) If the failure was caused by the lack of audit
record storage capacity, the operating system must continue generating audit records if
possible (automatically restarting the audit service if necessary), overwriting the
oldest audit records in a first-in-first-out manner.

2) If audit records are sent to a
centralized collection server and communication with this server is lost or the server
fails, the operating system must queue audit records locally until communication is
restored or until the audit records are retrieved manually. Upon restoration of the
connection to the centralized collection server, action should be taken to synchronize the
local audit data with the collection server. "
  desc 'check', "Verify the Ubuntu operating system takes the appropriate action when the audit storage
volume is full with the following command:

$ sudo grep '^disk_full_action'
/etc/audit/auditd.conf

disk_full_action = HALT

If the value of the
\"disk_full_action\" option is not \"SYSLOG\", \"SINGLE\", or \"HALT\", or the line is commented
out, this is a finding. "
  desc 'fix', "Configure the Ubuntu operating system to shut down by default upon audit failure (unless
availability is an overriding concern).

Add or update the following line (depending on
configuration, \"disk_full_action\" can be set to \"SYSLOG\", \"HALT\" or \"SINGLE\") in
\"/etc/audit/auditd.conf\" file:

disk_full_action = HALT

Restart the \"auditd\" service
so the changes take effect:

$ sudo systemctl restart auditd.service "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000047-GPOS-00023 '
  tag gid: 'V-238244 '
  tag rid: 'SV-238244r653907_rule '
  tag stig_id: 'UBTU-20-010118 '
  tag fix_id: 'F-41413r653906_fix '
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    describe auditd_conf do
      its('disk_full_action') { should_not be_empty }
      its('disk_full_action') { should cmp(/(?:SYSLOG|SINGLE|HALT)/i) }
    end
  end
end
