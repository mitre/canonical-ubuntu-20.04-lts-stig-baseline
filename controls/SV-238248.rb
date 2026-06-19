control 'SV-238248' do
  title 'The Ubuntu operating system must be configured so that the audit log directory is not write-accessible by unauthorized users.'
  desc 'If audit information were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit information, the operating system must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods, which will depend upon system architecture and design.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit information system activity.'
  desc 'check', 'Verify that the audit log directory has a mode of "0750" or less permissive.

Determine where the audit logs are stored with the following command:

$ sudo grep -iw ^log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Using the path of the directory containing the audit logs, determine if the directory has a mode of "0750" or less by using the following command:

$ sudo stat -c "%n %a" /var/log/audit /var/log/audit/*
/var/log/audit 750
/var/log/audit/audit.log 600

If the audit log directory has a mode more permissive than "0750", this is a finding.'
  desc 'fix', 'Configure the audit log directory to have a mode of "0750" or less permissive.

Determine where the audit logs are stored with the following command:

$ sudo grep -iw ^log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Using the path of the directory containing the audit logs, configure the audit log directory to have a mode of "0750" or less permissive by
 using the following command:

$ sudo chmod -R  g-w,o-rwx /var/log/audit'
  impact 0.5
  tag check_id: 'C-41458r653917_chk'
  tag severity: 'medium'
  tag gid: 'V-238248'
  tag rid: 'SV-238248r958438_rule'
  tag stig_id: 'UBTU-20-010128'
  tag gtitle: 'SRG-OS-000059-GPOS-00029'
  tag fix_id: 'F-41417r653918_fix'
  tag 'documentable'
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  audit_mode = input('expected_modes')['/var/log/audit']
  log_file = auditd_conf.log_file

  if log_file.nil? || log_file.strip.empty?
    describe 'auditd log_file setting' do
      it 'must be set in /etc/audit/auditd.conf' do
        fail_msg = "Unable to determine audit log directory: 'log_file' is not set in /etc/audit/auditd.conf"
        expect(log_file).not_to be_nil, fail_msg
        expect(log_file.to_s.strip).not_to be_empty, fail_msg
      end
    end
  else
    log_dir = File.dirname(log_file)

    describe directory(log_dir) do
      it { should_not be_more_permissive_than(audit_mode) }
    end
  end
end
