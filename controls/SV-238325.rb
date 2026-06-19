control 'SV-238325' do
  title 'The Ubuntu operating system must encrypt all stored passwords with a FIPS 140-2 approved cryptographic hashing algorithm.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc 'check', 'Verify that the shadow password suite configuration is set to encrypt passwords with a FIPS 140-2 approved cryptographic hashing algorithm.

Check the hashing algorithm that is being used to hash passwords with the following command:

$ cat /etc/login.defs | grep -i encrypt_method

ENCRYPT_METHOD SHA512

If "ENCRYPT_METHOD" does not equal SHA512 or greater, this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system to encrypt all stored passwords.

Edit/modify the following line in the "/etc/login.defs" file and set "ENCRYPT_METHOD" to SHA512:

ENCRYPT_METHOD SHA512'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag gid: 'V-238325'
  tag rid: 'SV-238325r971535_rule'
  tag stig_id: 'UBTU-20-010404'
  tag fix_id: 'F-41494r654149_fix'
  tag cci: ['CCI-000196', 'CCI-000803']
  tag nist: ['IA-5 (1) (c)', 'IA-7']
  tag 'host'
  tag 'container'

  weak_pw_hash_users = inspec.shadow.where { password !~ /^[*!]{1,2}.*$|^\$6\$.*$|^$/ }.users

  describe 'All stored passwords' do
    it 'should only be hashed with the SHA512 algorithm' do
      message = "Users without SHA512 hashes:\n\t- #{weak_pw_hash_users.join("\n\t- ")}"
      expect(weak_pw_hash_users).to be_empty, message
    end
  end
end
