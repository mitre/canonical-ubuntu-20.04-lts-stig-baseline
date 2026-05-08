control 'SV-238227' do
  title 'The Ubuntu operating system must prevent the use of dictionary words for passwords.'
  desc 'If the Ubuntu operating system allows the user to select passwords based on dictionary words, then this increases the chances of password compromise by increasing the opportunity for successful guesses and brute-force attacks.'
  desc 'check', 'Verify the Ubuntu operating system uses the "cracklib" library to prevent the use of dictionary words with the following command:

$ grep dictcheck /etc/security/pwquality.conf

dictcheck=1

If the "dictcheck" parameter is not set to "1" or is commented out, this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system to prevent the use of dictionary words for passwords.

Add or update the following line in the "/etc/security/pwquality.conf" file to include the "dictcheck=1" parameter:

dictcheck=1'
  impact 0.5
  tag check_id: 'C-41437r653854_chk'
  tag severity: 'medium'
  tag gid: 'V-238227'
  tag rid: 'SV-238227r991587_rule'
  tag stig_id: 'UBTU-20-010056'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag fix_id: 'F-41396r653855_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
