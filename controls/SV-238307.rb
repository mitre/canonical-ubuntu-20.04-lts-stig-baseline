control 'SV-238307' do
  title "The Ubuntu operating system must immediately notify the SA and ISSO (at a minimum) when
allocated audit record storage volume reaches 75% of the repository maximum audit record
storage capacity. "
  desc "If security personnel are not notified immediately when storage volume reaches 75%
utilization, they are unable to plan for audit record storage capacity expansion. "
  desc 'check', "Verify the Ubuntu operating system notifies the SA and ISSO (at a minimum) when allocated
audit record storage volume reaches 75% of the repository maximum audit record storage
capacity with the following command:

$ sudo grep ^space_left_action
/etc/audit/auditd.conf

space_left_action email

$ sudo grep ^space_left
/etc/audit/auditd.conf

space_left 250000

If the \"space_left\" parameter is missing,
set to blanks, or set to a value less than 25% of the space free in the allocated audit record
storage, this is a finding.

If the \"space_left_action\" parameter is missing or set to
blanks, this is a finding.

If the \"space_left_action\" is set to \"syslog\", the system logs
the event but does not generate a notification, and this is a finding.

If the
\"space_left_action\" is set to \"exec\", the system executes a designated script. If this
script informs the SA of the event, this is not a finding.

If the \"space_left_action\" is set
to \"email\", check the value of the \"action_mail_acct\" parameter with the following command:


$ sudo grep ^action_mail_acct /etc/audit/auditd.conf

action_mail_acct
root@localhost

The \"action_mail_acct\" parameter, if missing, defaults to \"root\". If the
\"action_mail_acct parameter\" is not set to the email address of the SA(s) and/or ISSO, this is
a finding.

Note: If the email address of the System Administrator
 is on a remote system, a
mail package must be available. "
  desc 'fix', "Edit \"/etc/audit/auditd.conf\" and set the \"space_left_action\" parameter to \"exec\" or
\"email\".

If the \"space_left_action\" parameter is set to \"email\", set the
\"action_mail_acct\" parameter to an email address for the SA and ISSO.

If the
\"space_left_action\" parameter is set to \"exec\", ensure the command being executed notifies
the SA and ISSO.

Edit \"/etc/audit/auditd.conf\" and set the \"space_left\" parameter to be at
least 25% of the repository maximum audit record storage capacity. "
  impact 0.3
  tag severity: 'low '
  tag gtitle: 'SRG-OS-000343-GPOS-00134 '
  tag gid: 'V-238307 '
  tag rid: 'SV-238307r853425_rule '
  tag stig_id: 'UBTU-20-010217 '
  tag fix_id: 'F-41476r654095_fix '
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    log_file = auditd_conf.log_file
    log_dir_exists = !log_file.nil? && !File.dirname(log_file).nil?

    if log_dir_exists
      email_to_notify = input('action_mail_acct')

      partition_threshold_mb = (filesystem(log_file).size_kb / 1024 * 0.25).to_i
      system_alert_configuration_mb = auditd_conf.space_left.to_i

      describe 'The space_left configuration' do
        subject { system_alert_configuration_mb }
        it { should >= partition_threshold_mb }
      end
      describe 'The space_left_action configuration' do
        subject { auditd_conf.space_left_action }
        it { should eq 'email' }
      end

      describe 'The action_mail_acct configuration' do
        subject { auditd_conf.action_mail_acct }
        it { should eq email_to_notify }
      end
    else
      describe('Audit file/directory for file ' + log_file + ' exists') do
        subject { log_dir_exists }
        it { should be true }
      end
    end
  end
end
