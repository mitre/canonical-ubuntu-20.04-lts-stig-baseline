control 'SV-238234' do
  title 'The Ubuntu operating system must prohibit password reuse for a minimum of five generations. '
  desc "Password complexity, or strength, is a measure of the effectiveness of a password in
resisting attempts at guessing and brute-force attacks. If the information system or
application allows the user to consecutively reuse their password when that password has
exceeded its defined lifetime, the end result is a password that is not changed as per policy
requirements.

 "
  desc 'check', "Verify the Ubuntu operating system prevents passwords from being reused for a minimum of five
generations by running the following command:

$ grep -i remember
/etc/pam.d/common-password

password [success=1 default=ignore] pam_unix.so obscure
sha512 shadow remember=5 rounds=5000

If the \"remember\" parameter value is not greater
than or equal to \"5\", is commented out, or is not set at all, this is a finding. "
  desc 'fix', "Configure the Ubuntu operating system to prevent passwords from being reused for a minimum of
five generations.

Add or modify the \"remember\" parameter value to the following line in
\"/etc/pam.d/common-password\" file:

password [success=1 default=ignore] pam_unix.so
obscure sha512 shadow remember=5 rounds=5000 "
  impact 0.3
  tag severity: 'low '
  tag gtitle: 'SRG-OS-000077-GPOS-00045 '
  tag satisfies: %w(SRG-OS-000077-GPOS-00045 SRG-OS-000073-GPOS-00041)
  tag gid: 'V-238234 '
  tag rid: 'SV-238234r832945_rule '
  tag stig_id: 'UBTU-20-010070 '
  tag fix_id: 'F-41403r832944_fix '
  tag cci: %w(CCI-000196 CCI-000200)
  tag nist: ['IA-5 (1) (c)', 'IA-5 (1) (e)']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    describe file('/etc/pam.d/common-password') do
      it { should exist }
    end

    describe command("grep -i remember /etc/pam.d/common-password | sed 's/.*remember=\\([^ ]*\\).*/\\1/'") do
      its('exit_status') { should eq 0 }
      its('stdout.strip') { should cmp >= 5 }
    end
  end
end
