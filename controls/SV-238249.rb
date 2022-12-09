control 'SV-238249' do
  title "The Ubuntu operating system must be configured so that audit configuration files are not
write-accessible by unauthorized users. "
  desc "Without the capability to restrict which roles and individuals can select which events are
audited, unauthorized personnel may be able to prevent the auditing of critical events.


Misconfigured audits may degrade the system's performance by overwhelming the audit log.
Misconfigured audits may also make it more difficult to establish, correlate, and
investigate the events relating to an incident or identify those responsible for one. "
  desc 'check', "Verify that \"/etc/audit/audit.rules\", \"/etc/audit/rules.d/*\", and
\"/etc/audit/auditd.conf\" files have a mode of \"0640\" or less permissive by using the
following command:

$ sudo ls -al /etc/audit/ /etc/audit/rules.d/

/etc/audit/:


-rw-r-----   1 root root   804 Nov 25 11:01 auditd.conf

-rw-r-----   1 root root  9128 Dec 27 09:56
audit.rules

-rw-r-----   1 root root  9373 Dec 27 09:56 audit.rules.prev

-rw-r-----   1 root
root   127 Feb  7  2018 audit-stop.rules

drwxr-x---   2 root root  4096 Dec 27 09:56 rules.d


/etc/audit/rules.d/:

-rw-r----- 1 root root 10357 Dec 27 09:56 stig.rules

If
\"/etc/audit/audit.rule\",\"/etc/audit/rules.d/*\", or \"/etc/audit/auditd.conf\" file
have a mode more permissive than \"0640\", this is a finding. "
  desc 'fix', "Configure \"/etc/audit/audit.rules\", \"/etc/audit/rules.d/*\", and
\"/etc/audit/auditd.conf\" files to have a mode of \"0640\" by using the following command:

$
sudo chmod -R 0640 /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/* "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000063-GPOS-00032 '
  tag gid: 'V-238249 '
  tag rid: 'SV-238249r653922_rule '
  tag stig_id: 'UBTU-20-010133 '
  tag fix_id: 'F-41418r653921_fix '
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    files1 = command('find /etc/audit/ -type f \( -iname \*.rules -o -iname \*.conf \)').stdout.strip.split("\n").entries
    files2 = command('find /etc/audit/rules.d/* -type f').stdout.strip.split("\n").entries

    audit_conf_files = files1 + files2

    audit_conf_files.each do |conf|
      describe file(conf) do
        it { should_not be_more_permissive_than('0640') }
      end
    end
  end
end
