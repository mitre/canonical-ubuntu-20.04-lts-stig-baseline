control 'SV-238368' do
  title "The Ubuntu operating system must implement non-executable data to protect its memory from
unauthorized code execution. "
  desc "Some adversaries launch attacks with the intent of executing code in non-executable regions
of memory or in memory locations that are prohibited. Security safeguards employed to
protect memory include, for example, data execution prevention and address space layout
randomization. Data execution prevention safeguards can either be hardware-enforced or
software-enforced with hardware providing the greater strength of mechanism.

Examples
of attacks are buffer overflow attacks. "
  desc 'check', "Verify the NX (no-execution) bit flag is set on the system with the following commands:

$
dmesg | grep -i \"execute disable\"
[    0.000000] NX (Execute Disable) protection: active

If
\"dmesg\" does not show \"NX (Execute Disable) protection: active\", check the cpuinfo settings
with the following command:

$ grep flags /proc/cpuinfo | grep -w nx | sort -u
flags       : fpu vme
de pse tsc ms nx rdtscp lm constant_tsc

If \"flags\" does not contain the \"nx\" flag, this is a
finding. "
  desc 'fix', "Configure the Ubuntu operating system to enable NX.

If \"nx\" is not showing up in
\"/proc/cpuinfo\", and the system's BIOS setup configuration permits toggling the No
Execution bit, set it to \"enable\". "
  impact 0.5
  tag severity: 'medium '
  tag gtitle: 'SRG-OS-000433-GPOS-00192 '
  tag gid: 'V-238368 '
  tag rid: 'SV-238368r853445_rule '
  tag stig_id: 'UBTU-20-010447 '
  tag fix_id: 'F-41537r654278_fix '
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    options = {
      assignment_regex: /^\s*([^:]*?)\s*:\s*(.*?)\s*$/,
    }
    describe.one do
      describe command('dmesg | grep NX').stdout.strip do
        it { should match(/.+(NX \(Execute Disable\) protection: active)/) }
      end
      describe parse_config_file('/proc/cpuinfo', options).flags.split(' ') do
        it { should include 'nx' }
      end
    end
  end
end
