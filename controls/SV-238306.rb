control 'SV-238306' do
  title 'The Ubuntu operating system audit event multiplexor must be configured to off-load audit logs onto a different system or storage media from the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Verify the audit event multiplexor is configured to offload audit records to a different system or storage media from the system being audited.

Check that audisp-remote plugin is installed:

$ sudo dpkg -s audispd-plugins

If status is "not installed", this is a finding.

Check that the records are being offloaded to a remote server with the following command:

$ sudo grep -i active /etc/audisp/plugins.d/au-remote.conf

active = yes

If "active" is not set to "yes", or the line is commented out, this is a finding.

Check that audisp-remote plugin is configured to send audit logs to a different system:

$ sudo grep -i ^remote_server /etc/audisp/audisp-remote.conf

remote_server = 192.168.122.126

If the "remote_server" parameter is not set, is set with a local address, or is set with an invalid address, this is a finding.'
  desc 'fix', %q(Configure the audit event multiplexor to offload audit records to a different system or storage media from the system being audited.

Install the audisp-remote plugin:

$ sudo apt-get install audispd-plugins -y

Set the audisp-remote plugin as active by editing the "/etc/audisp/plugins.d/au-remote.conf" file:

$ sudo sed -i -E 's/active\s*=\s*no/active = yes/' /etc/audisp/plugins.d/au-remote.conf

Set the address of the remote machine by editing the "/etc/audisp/audisp-remote.conf" file:

$ sudo sed -i -E 's/(remote_server\s*=).*/\1 <remote addr>/' /etc/audisp/audisp-remote.conf

where <remote addr> must be substituted by the address of the remote server receiving the audit log.

Make the audit service reload its configuration files:

$ sudo systemctl restart auditd.service)
  impact 0.3
  tag check_id: 'C-41516r654091_chk'
  tag severity: 'low'
  tag gid: 'V-238306'
  tag rid: 'SV-238306r958754_rule'
  tag stig_id: 'UBTU-20-010216'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-41475r654092_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe package('audispd-plugins') do
    it { should be_installed }
  end

  audisp_remote_plugin_config = '/etc/audisp/plugins.d/au-remote.conf'
  audisp_remote_plugin_config_exists = file(audisp_remote_plugin_config).exist?

  if audisp_remote_plugin_config_exists
    describe parse_config_file(audisp_remote_plugin_config) do
      its('active') { should cmp 'yes' }
    end
  else
    describe("#{audisp_remote_plugin_config} exists") do
      subject { audisp_remote_plugin_config_exists }
      it { should be true }
    end
  end

  audisp_remote_server_config = '/etc/audisp/audisp-remote.conf'
  audisp_remote_server_config_exists = file(audisp_remote_server_config).exist?
  audit_sp_remote_server = input('audit_sp_remote_server')

  if audisp_remote_server_config_exists
    describe parse_config_file(audisp_remote_server_config) do
      its('remote_server') { should cmp audit_sp_remote_server }
    end
  else
    describe("#{audisp_remote_server_config} exists") do
      subject { audisp_remote_server_config_exists }
      it { should be true }
    end
  end
end
