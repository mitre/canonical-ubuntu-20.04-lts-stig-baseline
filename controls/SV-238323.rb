control 'SV-238323' do
  title 'The Ubuntu operating system must limit the number of concurrent sessions to ten for all accounts and/or account types.'
  desc 'The Ubuntu operating system management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to DoS attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.'
  desc 'check', %q(Verify the Ubuntu operating system limits the number of concurrent sessions to 10 for all accounts and/or account types by running the following command:

$ grep maxlogins /etc/security/limits.conf /etc/security/limits.d/*.conf | grep -v '^#'

* hard maxlogins 10

If the "maxlogins" item is missing, or the value is not set to 10 or less, or is commented out, this is a finding.)
  desc 'fix', 'Configure the Ubuntu operating system to limit the number of concurrent sessions to 10 for all accounts and/or account types.

Add the following line to the top of the "/etc/security/limits.conf" file or to a file in "/etc/security/limits.d/":

* hard maxlogins 10'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000027-GPOS-00008'
  tag gid: 'V-238323'
  tag rid: 'SV-238323r1101671_rule'
  tag stig_id: 'UBTU-20-010400'
  tag fix_id: 'F-41492r1101670_fix'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  setting = 'maxlogins'
  expected_value = input('concurrent_sessions_permitted')

  limits_files = command('ls /etc/security/limits.d/*.conf').stdout.strip.split
  limits_files.append('/etc/security/limits.conf')

  # make sure that at least one limits.conf file has the correct setting
  globally_set = limits_files.any? { |lf| !limits_conf(lf).read_params['*'].nil? && limits_conf(lf).read_params['*'].include?(['hard', setting.to_s, expected_value.to_s]) }

  # make sure that no limits.conf file has a value that contradicts the global set
  failing_files = limits_files.select { |lf|
    limits_conf(lf).read_params.values.flatten(1).any? { |l|
      l[1].eql?(setting) && l[2].to_i > expected_value
    }
  }
  describe 'Limits files' do
    it "should limit concurrent sessions to #{expected_value} by default" do
      expect(globally_set).to eq(true), "No global ('*') setting for concurrent sessions found"
    end
    it 'should not have any conflicting settings' do
      expect(failing_files).to be_empty, "Files with incorrect '#{setting}' settings:\n\t- #{failing_files.join("\n\t- ")}"
    end
  end
end
