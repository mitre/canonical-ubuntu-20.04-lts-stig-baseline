control 'SV-238325' do
  title "The Ubuntu operating system must encrypt all stored passwords with a FIPS 140-2 approved
cryptographic hashing algorithm. "
  desc "Passwords need to be protected at all times, and encryption is the standard method for
protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear
text) and easily compromised. "
  desc 'check', "Verify that the shadow password suite configuration is set to encrypt passwords with a FIPS
140-2 approved cryptographic hashing algorithm.

Check the hashing algorithm that is
being used to hash passwords with the following command:

$ cat /etc/login.defs | grep -i
encrypt_method

ENCRYPT_METHOD SHA512

If \"ENCRYPT_METHOD\" does not equal SHA512 or
greater, this is a finding. "
  desc 'fix', "Configure the Ubuntu operating system to encrypt all stored passwords.

Edit/modify the
following line in the \"/etc/login.defs\" file and set \"ENCRYPT_METHOD\" to SHA512:


ENCRYPT_METHOD SHA512 "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000120-GPOS-00061 '
  tag gid: 'V-238325 '
  tag rid: 'SV-238325r654150_rule '
  tag stig_id: 'UBTU-20-010404 '
  tag fix_id: 'F-41494r654149_fix '
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
  tag 'host'

  if input('disable_fips')
    impact 0.0
    describe 'FIPS testing has been disabled' do
      skip 'This control has been set to Not Applicable, FIPS validation has been disabled with the `disable_fips` input'
    end
  elsif virtualization.system.eql?('docker')
    describe 'FIPS validation in a container must be reviewed manually' do
      skip 'FIPS validation in a container must be reviewed manually'
    end
  elsif virtualization.system.eql?('docker')
    describe 'Manual test' do
      skip 'This control must be reviewed manually'
    end
  else
    describe login_defs do
      its('ENCRYPT_METHOD') { should eq 'SHA512' }
    end
  end
end
