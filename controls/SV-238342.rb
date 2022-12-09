control 'SV-238342' do
  title 'The Ubuntu operating system must configure /var/log/syslog file to be owned by syslog. '
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error
messages are an indicator of an organization's operational state or can identify the
operating system or platform. Additionally, Personally Identifiable Information (PII)
and operational information must not be revealed through error messages to unauthorized
personnel or their designated representatives.

The structure and content of error
messages must be carefully considered by the organization and development team. The extent
to which the information system is able to identify and handle error conditions is guided by
organizational policy and operational requirements. "
  desc 'check', "Verify that the Ubuntu operating system configures the \"/var/log/syslog\" file to be owned by
syslog with the following command:

$ sudo stat -c \"%n %U\" /var/log/syslog

/var/log/syslog syslog

If the \"/var/log/syslog\" file is not owned by syslog, this is a
finding. "
  desc 'fix', "Configure the Ubuntu operating system to have syslog own the \"/var/log/syslog\" file by
running the following command:

$ sudo chown syslog /var/log/syslog "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000206-GPOS-00084 '
  tag gid: 'V-238342 '
  tag rid: 'SV-238342r654201_rule '
  tag stig_id: 'UBTU-20-010421 '
  tag fix_id: 'F-41511r654200_fix '
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
  tag 'host', 'container'

  describe file('/var/log/syslog') do
    its('owner') { should cmp 'syslog' }
  end
end
