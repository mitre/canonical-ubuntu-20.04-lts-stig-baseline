control 'SV-238369' do
  title 'The Ubuntu operating system must implement address space layout randomization to protect its memory from unauthorized code execution.'
  desc 'Some adversaries launch attacks with the intent of executing code in non-executable regions of memory or in memory locations that are prohibited. Security safeguards employed to protect memory include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can either be hardware-enforced or software-enforced with hardware providing the greater strength of mechanism.

Examples of attacks are buffer overflow attacks.'
  desc 'check', 'Verify the Ubuntu operating system implements address space layout randomization (ASLR) with the following command:

$ sudo sysctl kernel.randomize_va_space

kernel.randomize_va_space = 2

If nothing is returned, verify the kernel parameter "randomize_va_space" is set to "2" with the following command:

$ cat /proc/sys/kernel/randomize_va_space

2

If "kernel.randomize_va_space" is not set to "2", this is a finding.

Verify that a saved value of the "kernel.randomize_va_space" variable is not defined.

$ sudo egrep -R "^kernel.randomize_va_space=[^2]" /etc/sysctl.conf /etc/sysctl.d

If this returns a result, this is a finding.'
  desc 'fix', 'Remove the "kernel.randomize_va_space" entry found in the "/etc/sysctl.conf" file or any file located in the "/etc/sysctl.d/" directory.

After the line has been removed, the kernel settings from all system configuration files must be reloaded before any of the changes will take effect. Run the following command to reload all of the kernel system configuration files:

$ sudo sysctl --system'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000433-GPOS-00193'
  tag gid: 'V-238369'
  tag rid: 'SV-238369r958928_rule'
  tag stig_id: 'UBTU-20-010448'
  tag fix_id: 'F-41538r654281_fix'
  tag cci: ['CCI-002824', 'CCI-000366']
  tag nist: ['SI-16', 'CM-6 b']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  parameter = 'kernel.randomize_va_space'
  value = 2
  regexp = /^\s*#{parameter}\s*=\s*#{value}\s*$/

  describe kernel_parameter(parameter) do
    its('value') { should eq value }
  end

  search_results = command("/usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F #{parameter}").stdout.strip.split("\n")

  correct_result = search_results.any? { |line| line.match(regexp) }
  incorrect_results = search_results.map(&:strip).reject { |line| line.match(regexp) }

  describe 'Kernel config files' do
    it "should configure '#{parameter}'" do
      expect(correct_result).to eq(true), 'No config file was found that correctly sets this action'
    end
    unless incorrect_results.nil?
      it 'should not have incorrect or conflicting setting(s) in the config files' do
        expect(incorrect_results).to be_empty, "Incorrect or conflicting setting(s) found:\n\t- #{incorrect_results.join("\n\t- ")}"
      end
    end
  end
end
