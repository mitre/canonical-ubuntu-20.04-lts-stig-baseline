control 'SV-238223' do
  title "The Ubuntu operating system must enforce password complexity by requiring that at least one
numeric character be used. "
  desc "Use of a complex password helps to increase the time and resources required to compromise the
password. Password complexity, or strength, is a measure of the effectiveness of a password
in resisting attempts at guessing and brute-force attacks.

Password complexity is one
factor of several that determines how long it takes to crack a password. The more complex the
password, the greater the number of possible combinations that need to be tested before the
password is compromised. "
  desc 'check', "Verify the Ubuntu operating system enforces password complexity by requiring that at least
one numeric character be used.

Determine if the field \"dcredit\" is set in the
\"/etc/security/pwquality.conf\" file with the following command:

$ grep -i \"dcredit\"
/etc/security/pwquality.conf
dcredit=-1

If the \"dcredit\" parameter is greater than
\"-1\" or is commented out, this is a finding. "
  desc 'fix', "Configure the Ubuntu operating system to enforce password complexity by requiring that at
least one numeric character be used.

Add or update the \"/etc/security/pwquality.conf\"
file to contain the \"dcredit\" parameter:

dcredit=-1 "
  impact 0.3
  tag severity: 'low '
  tag gtitle: 'SRG-OS-000071-GPOS-00039 '
  tag gid: 'V-238223 '
  tag rid: 'SV-238223r653844_rule '
  tag stig_id: 'UBTU-20-010052 '
  tag fix_id: 'F-41392r653843_fix '
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
  tag 'host', 'container'

  config_file = '/etc/security/pwquality.conf'
  config_file_exists = file(config_file).exist?

  if config_file_exists
    describe parse_config_file(config_file) do
      its('dcredit') { should cmp '-1' }
    end
  else
    describe(config_file + ' exists') do
      subject { config_file_exists }
      it { should be true }
    end
  end
end
