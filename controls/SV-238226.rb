control 'SV-238226' do
  title "The Ubuntu operating system must enforce password complexity by requiring that at least one
special character be used. "
  desc "Use of a complex password helps to increase the time and resources required to compromise the
password. Password complexity or strength is a measure of the effectiveness of a password in
resisting attempts at guessing and brute-force attacks.

Password complexity is one
factor in determining how long it takes to crack a password. The more complex the password, the
greater the number of possible combinations that need to be tested before the password is
compromised.

Special characters are those characters that are not alphanumeric.
Examples include: ~ ! @ # $ % ^ *. "
  desc 'check', "Determine if the field \"ocredit\" is set in the \"/etc/security/pwquality.conf\" file with the
following command:

$ grep -i \"ocredit\" /etc/security/pwquality.conf
ocredit=-1

If
the \"ocredit\" parameter is greater than \"-1\" or is commented out, this is a finding. "
  desc 'fix', "Configure the Ubuntu operating system to enforce password complexity by requiring that at
least one special character be used.

Add or update the following line in the
\"/etc/security/pwquality.conf\" file to include the \"ocredit=-1\" parameter:


ocredit=-1 "
  impact 0.3
  tag severity: 'low '
  tag gtitle: 'SRG-OS-000266-GPOS-00101 '
  tag gid: 'V-238226 '
  tag rid: 'SV-238226r653853_rule '
  tag stig_id: 'UBTU-20-010055 '
  tag fix_id: 'F-41395r653852_fix '
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
  tag 'host', 'container'

  config_file = '/etc/security/pwquality.conf'
  config_file_exists = file(config_file).exist?

  if config_file_exists
    describe parse_config_file(config_file) do
      its('ocredit') { should cmp '-1' }
    end
  else
    describe(config_file + ' exists') do
      subject { config_file_exists }
      it { should be true }
    end
  end
end
