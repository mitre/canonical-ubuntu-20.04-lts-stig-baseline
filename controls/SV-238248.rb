control 'SV-238248' do
  title "The Ubuntu operating system must be configured so that the audit log directory is not
write-accessible by unauthorized users. "
  desc "If audit information were to become compromised, then forensic analysis and discovery of the
true source of potentially malicious system activity is impossible to achieve.

To ensure
the veracity of audit information, the operating system must protect audit information from
unauthorized deletion. This requirement can be achieved through multiple methods, which
will depend upon system architecture and design.

Audit information includes all
information (e.g., audit records, audit settings, audit reports) needed to successfully
audit information system activity. "
  desc 'check', "Verify that the audit log directory has a mode of \"0750\" or less permissive.

Determine where
the audit logs are stored with the following command:

$ sudo grep -iw ^log_file
/etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Using the path of the
directory containing the audit logs, determine if the directory has a mode of \"0750\" or less by
using the following command:

$ sudo stat -c \"%n %a\" /var/log/audit /var/log/audit/*

/var/log/audit 750
/var/log/audit/audit.log 600

If the audit log directory has a mode
more permissive than \"0750\", this is a finding. "
  desc 'fix', "Configure the audit log directory to have a mode of \"0750\" or less permissive.

Determine
where the audit logs are stored with the following command:

$ sudo grep -iw ^log_file
/etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Using the path of the
directory containing the audit logs, configure the audit log directory to have a mode of
\"0750\" or less permissive by
 using the following command:

$ sudo chmod -R  g-w,o-rwx
/var/log/audit "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000059-GPOS-00029 '
  tag gid: 'V-238248 '
  tag rid: 'SV-238248r653919_rule '
  tag stig_id: 'UBTU-20-010128 '
  tag fix_id: 'F-41417r653918_fix '
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
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
      describe directory(File.dirname(log_file)) do
        it { should_not be_more_permissive_than('0750') }
      end
    else
      describe('Audit directory for file ' + log_file + ' exists') do
        subject { log_dir_exists }
        it { should be true }
      end
    end
  end
end
