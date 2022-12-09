control 'SV-238373' do
  title "The Ubuntu operating system must display the date and time of the last successful account
logon upon logon. "
  desc "Configuration settings are the set of parameters that can be changed in hardware, software,
or firmware components of the system that affect the security posture and/or functionality
of the system. Security-related parameters are those parameters impacting the security
state of the system, including the parameters required to satisfy other security control
requirements. Security-related parameters include, for example: registry settings;
account, file, directory permission settings; and settings for functions, ports,
protocols, services, and remote connections. "
  desc 'check', "Verify users are provided with feedback on when account accesses last occurred.

Check that
\"pam_lastlog\" is used and not silent with the following command:

$ grep pam_lastlog
/etc/pam.d/login

session     required      pam_lastlog.so showfailed

If \"pam_lastlog\" is
missing from \"/etc/pam.d/login\" file, is not \"required\", or the \"silent\" option is present,
this is a finding. "
  desc 'fix', "Configure the Ubuntu operating system to provide users with feedback on when account
accesses last occurred by setting the required configuration options in
\"/etc/pam.d/login\".

Add the following line to the top of \"/etc/pam.d/login\":

session
required      pam_lastlog.so showfailed "
  impact 0.3
  tag severity: 'low '
  tag gtitle: 'SRG-OS-000480-GPOS-00227 '
  tag gid: 'V-238373 '
  tag rid: 'SV-238373r858539_rule '
  tag stig_id: 'UBTU-20-010453 '
  tag fix_id: 'F-41542r654293_fix '
  tag cci: ['CCI-000052']
  tag nist: ['AC-9']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    describe command('grep pam_lastlog /etc/pam.d/login') do
      its('exit_status') { should eq 0 }
      its('stdout.strip') { should match(/^\s*session\s+required\s+pam_lastlog.so/) }
      its('stdout.strip') { should_not match(/^\s*session\s+required\s+pam_lastlog.so[\s\w\d\=]+.*silent/) }
    end
  end
end
