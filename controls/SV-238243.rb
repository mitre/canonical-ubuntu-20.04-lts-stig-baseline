control 'SV-238243' do
  title "The Ubuntu operating system must alert the ISSO and SA (at a minimum) in the event of an audit
processing failure. "
  desc "It is critical for the appropriate personnel to be aware if a system is at risk of failing to
process audit logs as required. Without this notification, the security personnel may be
unaware of an impending failure of the audit capability, and system operation may be
adversely affected.

Audit processing failures include software/hardware errors,
failures in the audit capturing mechanisms, and audit storage capacity being reached or
exceeded.

This requirement applies to each audit data storage repository (i.e., distinct
information system component where audit records are stored), the centralized audit
storage capacity of organizations (i.e., all audit data storage repositories combined), or
both. "
  desc 'check', "Verify that the SA and ISSO (at a minimum) are notified in the event of an audit processing
failure with the following command:

$ sudo grep '^action_mail_acct = root'
/etc/audit/auditd.conf

action_mail_acct = &lt;administrator_account&gt;

If the
value of the \"action_mail_acct\" keyword is not set to an accounts for security personnel, the
\"action_mail_acct\" keyword is missing, or the returned line is commented out, this is a
finding. "
  desc 'fix', "Configure \"auditd\" service to notify the SA and ISSO in the event of an audit processing
failure.

Edit the following line in \"/etc/audit/auditd.conf\" to ensure administrators
are notified via email for those situations:

action_mail_acct =
&lt;administrator_account&gt;

Note: Change \"administrator_account\" to an account for
security personnel.

Restart the \"auditd\" service so the changes take effect:

$ sudo
systemctl restart auditd.service "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000046-GPOS-00022 '
  tag gid: 'V-238243 '
  tag rid: 'SV-238243r653904_rule '
  tag stig_id: 'UBTU-20-010117 '
  tag fix_id: 'F-41412r653903_fix '
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    action_mail_acct = auditd_conf.action_mail_acct
    security_accounts = input('action_mail_acct')

    describe 'System Administrator (SA) and Information System Security Officer (ISSO) are notified in the event of an audit processing failure' do
      subject { security_accounts }
      it { should cmp action_mail_acct }
    end
  end
end
