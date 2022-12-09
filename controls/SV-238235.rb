control 'SV-238235' do
  title "The Ubuntu operating system must automatically lock an account until the locked account is
released by an administrator when three unsuccessful logon attempts have been made. "
  desc "By limiting the number of failed logon attempts, the risk of unauthorized system access via
user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by
locking the account.

 "
  desc 'check', "Verify that the Ubuntu operating system utilizes the \"pam_faillock\" module with the
following command:
$ grep faillock /etc/pam.d/common-auth

auth     [default=die]
pam_faillock.so authfail
auth     sufficient     pam_faillock.so authsucc

If the
pam_faillock.so module is not present in the \"/etc/pam.d/common-auth\" file, this is a
finding.

Verify the pam_faillock module is configured to use the following options:
$
sudo egrep 'silent|audit|deny|fail_interval| unlock_time'
/etc/security/faillock.conf

audit
silent
deny = 3
fail_interval = 900
unlock_time =
0

If the \"silent\" keyword is missing or commented out, this is a finding.
If the \"audit\"
keyword is missing or commented out, this is a finding.
If the \"deny\" keyword is missing,
commented out, or set to a value greater than 3, this is a finding.
If the \"fail_interval\"
keyword is missing, commented out, or set to a value greater than 900, this is a finding.
If the
\"unlock_time\" keyword is missing, commented out, or not set to 0, this is a finding. "
  desc 'fix', "Configure the Ubuntu operating system to utilize the \"pam_faillock\" module.

Edit the
/etc/pam.d/common-auth file.

Add the following lines below the \"auth\" definition for
pam_unix.so:
auth     [default=die]  pam_faillock.so authfail
auth     sufficient
pam_faillock.so authsucc

Configure the \"pam_faillock\" module to use the following
options:

Edit the /etc/security/faillock.conf file and add/update the following
keywords and values:
audit
silent
deny = 3
fail_interval = 900
unlock_time = 0 "
  impact 0.3
  tag severity: 'low '
  tag gtitle: 'SRG-OS-000329-GPOS-00128 '
  tag satisfies: %w(SRG-OS-000329-GPOS-00128 SRG-OS-000021-GPOS-00005)
  tag gid: 'V-238235 '
  tag rid: 'SV-238235r853414_rule '
  tag stig_id: 'UBTU-20-010072 '
  tag fix_id: 'F-41404r802382_fix '
  tag cci: %w(CCI-000044 CCI-002238)
  tag nist: ['AC-7 a', 'AC-7 b']
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

    describe command('grep pam_tally /etc/pam.d/common-auth') do
      its('exit_status') { should eq 0 }
      its('stdout.strip') { should match(/^\s*auth\s+required\s+pam_tally2.so\s+.*onerr=fail\s+deny=3($|\s+.*$)/) }
      its('stdout.strip') { should_not match(/^\s*auth\s+required\s+pam_tally2.so\s+.*onerr=fail\s+deny=3\s+.*unlock_time.*$/) }
    end
  end
end
