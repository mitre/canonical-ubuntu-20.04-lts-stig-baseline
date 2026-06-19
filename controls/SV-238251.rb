control 'SV-238251' do
  title 'The Ubuntu operating system must permit only authorized groups to own the audit configuration files.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events.

Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Verify that "/etc/audit/audit.rules", "/etc/audit/rules.d/*", and "/etc/audit/auditd.conf" files are owned by root group by using the following command:

$ sudo ls -al /etc/audit/ /etc/audit/rules.d/

/etc/audit/:

-rw-r-----   1 root root   804 Nov 25 11:01 auditd.conf

-rw-r-----   1 root root  9128 Dec 27 09:56 audit.rules

-rw-r-----   1 root root  9373 Dec 27 09:56 audit.rules.prev

-rw-r-----   1 root root   127 Feb  7  2018 audit-stop.rules

drwxr-x---   2 root root  4096 Dec 27 09:56 rules.d

/etc/audit/rules.d/:

-rw-r----- 1 root root 10357 Dec 27 09:56 stig.rules

If the "/etc/audit/audit.rules", "/etc/audit/rules.d/*", or "/etc/audit/auditd.conf" file is owned by a group other than "root", this is a finding.'
  desc 'fix', 'Configure "/etc/audit/audit.rules", "/etc/audit/rules.d/*", and "/etc/audit/auditd.conf" files to be owned by root group by using the following command:

$ sudo chown :root /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/*'
  impact 0.5
  tag check_id: 'C-41461r653926_chk'
  tag severity: 'medium'
  tag gid: 'V-238251'
  tag rid: 'SV-238251r958444_rule'
  tag stig_id: 'UBTU-20-010135'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag fix_id: 'F-41420r653927_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
  tag 'host'

  if %w[docker podman kubepods lxc].include?(virtualization.system)
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    log_file = auditd_conf.log_file
    admin_groups = input('admin_groups')

    log_file_exists = !log_file.nil?
    if log_file_exists
      describe file(log_file) do
        its('group') { should be_in admin_groups }
      end
    else
      describe("Audit log file #{log_file} exists") do
        subject { log_file_exists }
        it { should be true }
      end
    end
  end
end
