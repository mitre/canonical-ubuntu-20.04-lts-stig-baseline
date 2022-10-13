# encoding: UTF-8

control 'V-238247' do
  title "The Ubuntu operating system must permit only authorized groups
ownership of the audit log files."
  desc  "Unauthorized disclosure of audit records can reveal system and
configuration data to attackers, thus compromising its confidentiality.

    Audit information includes all information (e.g., audit records, audit
settings, audit reports) needed to successfully audit operating system activity.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify the group owner is set to own newly created audit logs in the audit
configuration file with the following command:

    $ sudo grep -iw log_group /etc/audit/auditd.conf
    log_group = adm

    If the value of the \"log_group\" parameter is other than \"root\" or
\"adm\", this is a finding.

    Determine where the audit logs are stored with the following command:

    $ sudo grep -iw log_file /etc/audit/auditd.conf
    log_file = /var/log/audit/audit.log

    Using the path of the directory containing the audit logs, determine if the
audit log files are owned by the \"root\" or \"adm\" group by using the
following command:

    $ sudo stat -c \"%n %G\" /var/log/audit/*
    /var/log/audit/audit.log root

    If the audit log files are owned by a group other than \"root\" or \"adm\",
this is a finding.
  "
  desc  'fix', "
    Configure the audit log directory and its underlying files to be owned by
\"adm\" group.

    Determine where the audit logs are stored with the following command:

    $ sudo grep -iw ^log_file /etc/audit/auditd.conf
    log_file = /var/log/audit/audit.log

    Using the path of the directory containing the audit logs, configure the
audit log files to be owned by \"adm\" group by using the following command:

    $ sudo chown :adm /var/log/audit/

    Set the \"log_group\" parameter of the audit configuration file to the
\"adm\" value so that when a new log file is created, its group owner is
properly set:

    $ sed -i '/^log_group/D' /etc/audit/auditd.conf
    $ sed -i /^log_file/a'log_group = adm' /etc/audit/auditd.conf

    Last, signal the audit daemon to reload the configuration file:

    $ sudo systemctl kill auditd -s SIGHUP\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028',
'SRG-OS-000059-GPOS-00029']
  tag gid: 'V-238247'
  tag rid: 'SV-238247r653916_rule'
  tag stig_id: 'UBTU-20-010124'
  tag fix_id: 'F-41416r653915_fix'
  tag cci: ['CCI-000162']
  tag legacy: []
  tag nist: ['AU-9']

  log_file = auditd_conf.log_file

  log_file_exists = !log_file.nil?
  if log_file_exists
    describe file(log_file) do
      its('group') { should cmp 'root' }
    end
  else
    describe ('Audit log file ' + log_file + ' exists') do
      subject { log_file_exists }
      it { should be true }
    end
  end
end

