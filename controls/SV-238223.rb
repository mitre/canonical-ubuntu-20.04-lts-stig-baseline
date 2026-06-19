control 'SV-238223' do
  title 'The Ubuntu operating system must enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify the Ubuntu operating system enforces password complexity by requiring that at least one numeric character be used.

Determine if the field "dcredit" is set in the "/etc/security/pwquality.conf" file with the following command:

$ grep -i "dcredit" /etc/security/pwquality.conf
dcredit=-1

If the "dcredit" parameter is greater than "-1" or is commented out, this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system to enforce password complexity by requiring that at least one numeric character be used.

Add or update the "/etc/security/pwquality.conf" file to contain the "dcredit" parameter:

dcredit=-1'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000071-GPOS-00039'
  tag gid: 'V-238223'
  tag rid: 'SV-238223r1015146_rule'
  tag stig_id: 'UBTU-20-010052'
  tag fix_id: 'F-41392r653843_fix'
  tag cci: ['CCI-000194', 'CCI-004066', 'CCI-004065']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (h)', 'IA-5 (1) (g)']
  tag 'host'
  tag 'container'

  describe 'pwquality.conf settings' do
    let(:config) { parse_config_file('/etc/security/pwquality.conf', multiple_values: true) }
    let(:setting) { 'dcredit' }
    let(:value) { Array(config.params[setting]) }

    it 'has `dcredit` set' do
      expect(value).not_to be_empty, 'dcredit is not set in pwquality.conf'
    end

    it 'only sets `dcredit` once' do
      expect(value.length).to eq(1), 'dcredit is commented or set more than once in pwquality.conf'
    end

    it 'does not set `dcredit` to a positive value' do
      expect(value.first.to_i).to be < 0, 'dcredit is not set to a negative value in pwquality.conf'
    end
  end
end
