control 'SV-238250' do
  title "The Ubuntu operating system must permit only authorized accounts to own the audit
configuration files. "
  desc "Without the capability to restrict which roles and individuals can select which events are
audited, unauthorized personnel may be able to prevent the auditing of critical events.


Misconfigured audits may degrade the system's performance by overwhelming the audit log.
Misconfigured audits may also make it more difficult to establish, correlate, and
investigate the events relating to an incident or identify those responsible for one. "
  desc 'check', "Verify that \"/etc/audit/audit.rules\", \"/etc/audit/rules.d/*\" and
\"/etc/audit/auditd.conf\" files are owned by root account by using the following command:


$ sudo ls -al /etc/audit/ /etc/audit/rules.d/

/etc/audit/:

drwxr-x---   3 root root
4096 Nov 25 11:02 .

drwxr-xr-x 130 root root 12288 Dec 19 13:42 ..

-rw-r-----   1 root root   804
Nov 25 11:01 auditd.conf

-rw-r-----   1 root root  9128 Dec 27 09:56 audit.rules

-rw-r-----
1 root root  9373 Dec 27 09:56 audit.rules.prev

-rw-r-----   1 root root   127 Feb  7  2018
audit-stop.rules

drwxr-x---   2 root root  4096 Dec 27 09:56 rules.d


/etc/audit/rules.d/:

drwxr-x--- 2 root root  4096 Dec 27 09:56 .

drwxr-x--- 3 root root
4096 Nov 25 11:02 ..

-rw-r----- 1 root root 10357 Dec 27 09:56 stig.rules

If the
\"/etc/audit/audit.rules\", \"/etc/audit/rules.d/*\", or \"/etc/audit/auditd.conf\" file
is owned by a user other than \"root\", this is a finding. "
  desc 'fix', "Configure \"/etc/audit/audit.rules\", \"/etc/audit/rules.d/*\" and
\"/etc/audit/auditd.conf\" files to be owned by root user by using the following command:

$
sudo chown root /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/* "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000063-GPOS-00032 '
  tag gid: 'V-238250 '
  tag rid: 'SV-238250r653925_rule '
  tag stig_id: 'UBTU-20-010134 '
  tag fix_id: 'F-41419r653924_fix '
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
        its('owner') { should cmp 'root' }
      end
    end
  end
end
