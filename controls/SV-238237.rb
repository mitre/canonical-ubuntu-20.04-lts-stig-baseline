control 'SV-238237' do
  title "The Ubuntu operating system must enforce a delay of at least 4 seconds between logon prompts
following a failed logon attempt. "
  desc "Limiting the number of logon attempts over a certain time interval reduces the chances that an
unauthorized user may gain access to an account. "
  desc 'check', "Verify the Ubuntu operating system enforces a delay of at least 4 seconds between logon
prompts following a failed logon attempt with the following command:

$ grep pam_faildelay
/etc/pam.d/common-auth

auth    required    pam_faildelay.so    delay=4000000

If the line is
not present or is commented out, this is a finding. "
  desc 'fix', "Configure the Ubuntu operating system to enforce a delay of at least 4 seconds between logon
prompts following a failed logon attempt.

Edit the file \"/etc/pam.d/common-auth\" and set
the parameter \"pam_faildelay\" to a value of  4000000 or greater:

auth    required
pam_faildelay.so    delay=4000000 "
  impact 0.3
  tag severity: 'low '
  tag gtitle: 'SRG-OS-000480-GPOS-00226 '
  tag gid: 'V-238237 '
  tag rid: 'SV-238237r653886_rule '
  tag stig_id: 'UBTU-20-010075 '
  tag fix_id: 'F-41406r653885_fix '
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    describe file('/etc/pam.d/common-auth') do
      it { should exist }
    end

    describe command('grep pam_faildelay /etc/pam.d/common-auth') do
      its('exit_status') { should eq 0 }
      its('stdout.strip') { should match(/^\s*auth\s+required\s+pam_faildelay.so\s+.*delay=([4-9][\d]{6,}|[1-9][\d]{7,}).*$/) }
    end

    file('/etc/pam.d/common-auth').content.to_s.scan(/^\s*auth\s+required\s+pam_faildelay.so\s+.*delay=(\d+).*$/).flatten.each do |entry|
      describe entry do
        it { should cmp >= 4_000_000 }
      end
    end
  end
end
