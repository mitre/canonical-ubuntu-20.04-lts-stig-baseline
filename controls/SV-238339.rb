control 'SV-238339' do
  title 'The Ubuntu operating system must configure the /var/log directory to be owned by root. '
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error
messages are an indicator of an organization's operational state or can identify the
operating system or platform. Additionally, Personally Identifiable Information (PII)
and operational information must not be revealed through error messages to unauthorized
personnel or their designated representatives.

The structure and content of error
messages must be carefully considered by the organization and development team. The extent
to which the information system is able to identify and handle error conditions is guided by
organizational policy and operational requirements. "
  desc 'check', "Verify the Ubuntu operating system configures the \"/var/log\" directory to be owned by root
with the following command:

$ sudo stat -c \"%n %U\" /var/log
/var/log root

If the
\"/var/log\" directory is not owned by root, this is a finding. "
  desc 'fix', "Configure the Ubuntu operating system to have root own the \"/var/log\" directory by running
the following command:

$ sudo chown root /var/log "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000206-GPOS-00084 '
  tag gid: 'V-238339 '
  tag rid: 'SV-238339r654192_rule '
  tag stig_id: 'UBTU-20-010418 '
  tag fix_id: 'F-41508r654191_fix '
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
  tag 'host', 'container'

  describe directory('/var/log') do
    its('owner') { should cmp 'root' }
  end
end
