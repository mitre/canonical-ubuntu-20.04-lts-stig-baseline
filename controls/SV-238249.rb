control 'SV-238249' do
  title 'The Ubuntu operating system must be configured so that audit configuration files are not write-accessible by unauthorized users.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events.

Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Verify that "/etc/audit/audit.rules", "/etc/audit/rules.d/*", and "/etc/audit/auditd.conf" files have a mode of "0640" or less permissive by using the following command:

$ sudo ls -al /etc/audit/ /etc/audit/rules.d/

/etc/audit/:

-rw-r-----   1 root root   804 Nov 25 11:01 auditd.conf

-rw-r-----   1 root root  9128 Dec 27 09:56 audit.rules

-rw-r-----   1 root root  9373 Dec 27 09:56 audit.rules.prev

-rw-r-----   1 root root   127 Feb  7  2018 audit-stop.rules

drwxr-x---   2 root root  4096 Dec 27 09:56 rules.d

/etc/audit/rules.d/:

-rw-r----- 1 root root 10357 Dec 27 09:56 stig.rules

If "/etc/audit/audit.rule","/etc/audit/rules.d/*", or "/etc/audit/auditd.conf" file have a mode more permissive than "0640", this is a finding.'
  desc 'fix', 'Configure "/etc/audit/audit.rules", "/etc/audit/rules.d/*", and "/etc/audit/auditd.conf" files to have a mode of "0640" by using the following command:

$ sudo chmod -R 0640 /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/*'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag gid: 'V-238249'
  tag rid: 'SV-238249r958444_rule'
  tag stig_id: 'UBTU-20-010133'
  tag fix_id: 'F-41418r653921_fix'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  expected_mode = input('audit_conf_mode')
  rules_dir_files = command("find /etc/audit/rules.d -maxdepth 1 -type f -printf '%p\\n' 2>/dev/null").stdout.split("\n").reject(&:empty?)
  audit_files = ['/etc/audit/auditd.conf', '/etc/audit/audit.rules'] + rules_dir_files
  existing_files = audit_files.select { |p| file(p).exist? }
  failing_files = existing_files.select { |p| file(p).more_permissive_than?(expected_mode) }

  describe 'Audit configuration files' do
    subject { failing_files }
    it "should be no more permissive than '#{expected_mode}'" do
      expect(subject).to be_empty, "Failing files:\n\t- #{subject.join("\n\t- ")}"
    end
  end
end
