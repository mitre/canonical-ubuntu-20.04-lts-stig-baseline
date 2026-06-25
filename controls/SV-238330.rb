control 'SV-238330' do
  title 'The Ubuntu operating system must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.'
  desc 'Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.

Operating systems need to track periods of inactivity and disable application identifiers after 35 days of inactivity.'
  desc 'check', 'Verify the account identifiers (individuals, groups, roles, and devices) are disabled after 35 days of inactivity with the following command:

Check the account inactivity value by performing the following command:

$ sudo grep INACTIVE /etc/default/useradd

INACTIVE=35

If "INACTIVE" is not set to a value 0<[VALUE]<=35, or is commented out, this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system to disable account identifiers after 35 days of inactivity since the password expiration.

Run the following command to change the configuration for adduser:

$ sudo useradd -D -f 35

Note: DoD recommendation is 35 days, but a lower value is acceptable. The value "0" will disable the account immediately after the password expires.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag gid: 'V-238330'
  tag rid: 'SV-238330r1015154_rule'
  tag stig_id: 'UBTU-20-010409'
  tag fix_id: 'F-41499r928524_fix'
  tag cci: ['CCI-000795', 'CCI-003627', 'CCI-003628']
  tag nist: ['IA-4 e', 'AC-2 (3) (a)', 'AC-2 (3) (b)']
  tag 'host'
  tag 'container'

  days_of_inactivity = input('days_of_inactivity')
  useradd_config_file = input('useradd_config_file')

  describe 'Useradd configuration' do
    useradd_config = parse_config_file(useradd_config_file)
    useradd_config_params = useradd_config.params

    it 'should parse parameters' do
      expect(useradd_config_params).not_to be_nil
    end

    unless useradd_config_params.nil?
      describe 'INACTIVE setting' do
        subject { useradd_config_params['INACTIVE'] }
        it { should cmp >= 0 }
        it { should cmp <= days_of_inactivity }
        it { should_not cmp '-1' }
      end
    end
  end
end
