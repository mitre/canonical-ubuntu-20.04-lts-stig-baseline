control 'SV-251505' do
  title 'The Ubuntu operating system must disable automatic mounting of Universal Serial Bus (USB) mass storage driver.'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

Peripherals include, but are not limited to, such devices as flash drives, external storage, and printers.'
  desc 'check', 'Verify that Ubuntu operating system disables ability to load the USB storage kernel module.

# grep usb-storage /etc/modprobe.d/* | grep "/bin/false"

install usb-storage /bin/false

If the command does not return any output, or the line is commented out, this is a finding.

Verify the operating system disables the ability to use USB mass storage device.

# grep usb-storage /etc/modprobe.d/* | grep -i "blacklist"

blacklist usb-storage

If the command does not return any output, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system to disable using the USB storage kernel module.

Create a file under "/etc/modprobe.d" to contain the following:

# sudo su -c "echo install usb-storage /bin/false >> /etc/modprobe.d/DISASTIG.conf"

Configure the operating system to disable the ability to use USB mass storage devices.

# sudo su -c "echo blacklist usb-storage >> /etc/modprobe.d/DISASTIG.conf"'
  impact 0.5
  tag check_id: 'C-54940r942849_chk'
  tag severity: 'medium'
  tag gid: 'V-251505'
  tag rid: 'SV-251505r958820_rule'
  tag stig_id: 'UBTU-20-010461'
  tag gtitle: 'SRG-OS-000378-GPOS-00163'
  tag fix_id: 'F-54894r942850_fix'
  tag 'documentable'
  tag cci: ['CCI-001958', 'CCI-003959']
  tag nist: ['IA-3', 'CM-7 (9) (b)']
  tag 'host'

  if %w[docker podman kubepods lxc].include?(virtualization.system)
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    describe command('grep usb-storage /etc/modprobe.d/* | grep "/bin/false"') do
      its('stdout') { should_not be_empty }
    end

    describe command('grep usb-storage /etc/modprobe.d/* | grep -i "blacklist"') do
      its('stdout') { should_not be_empty }
    end
  end
end
