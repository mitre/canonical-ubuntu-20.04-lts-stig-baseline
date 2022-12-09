control 'SV-238306' do
  title "The Ubuntu operating system audit event multiplexor must be configured to off-load audit
logs onto a different system or storage media from the system being audited. "
  desc "Information stored in one location is vulnerable to accidental or incidental deletion or
alteration.

Off-loading is a common process in information systems with limited audit
storage capacity.

 "
  desc 'check', "Verify the audit event multiplexor is configured to offload audit records to a different
system or storage media from the system being audited.

Check that audisp-remote plugin is
installed:

$ sudo dpkg -s audispd-plugins

If status is \"not installed\", this is a
finding.

Check that the records are being offloaded to a remote server with the following
command:

$ sudo grep -i active /etc/audisp/plugins.d/au-remote.conf

active = yes

If
\"active\" is not set to \"yes\", or the line is commented out, this is a finding.

Check that
audisp-remote plugin is configured to send audit logs to a different system:

$ sudo grep -i
^remote_server /etc/audisp/audisp-remote.conf

remote_server = 192.168.122.126

If
the \"remote_server\" parameter is not set, is set with a local address, or is set with an invalid
address, this is a finding. "
  desc 'fix', "Configure the audit event multiplexor to offload audit records to a different system or
storage media from the system being audited.

Install the audisp-remote plugin:

$ sudo
apt-get install audispd-plugins -y

Set the audisp-remote plugin as active by editing the
\"/etc/audisp/plugins.d/au-remote.conf\" file:

$ sudo sed -i -E
's/active\\s*=\\s*no/active = yes/' /etc/audisp/plugins.d/au-remote.conf

Set the
address of the remote machine by editing the \"/etc/audisp/audisp-remote.conf\" file:

$
sudo sed -i -E 's/(remote_server\\s*=).*/\\1 &lt;remote addr&gt;/'
/etc/audisp/audisp-remote.conf

where &lt;remote addr&gt; must be substituted by the
address of the remote server receiving the audit log.

Make the audit service reload its
configuration files:

$ sudo systemctl restart auditd.service "
  impact 0.3
  tag severity: 'low '
  tag gtitle: 'SRG-OS-000342-GPOS-00133 '
  tag satisfies: %w(SRG-OS-000342-GPOS-00133 SRG-OS-000479-GPOS-00224)
  tag gid: 'V-238306 '
  tag rid: 'SV-238306r853424_rule '
  tag stig_id: 'UBTU-20-010216 '
  tag fix_id: 'F-41475r654092_fix '
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable to a container' do
      skip 'Control not applicable to a container'
    end
  else
    config_file = input('audispremote_config_file')
    config_file_exists = file(config_file).exist?
    audit_sp_remote_server = input('audit_sp_remote_server')

    describe package('audispd-plugins') do
      it { should be_installed }
    end

    if config_file_exists
      describe parse_config_file(config_file) do
        its('active') { should cmp 'yes' }
        its('remote_server') { should cmp audit_sp_remote_server }
      end
    else
      describe(config_file + ' exists') do
        subject { config_file_exists }
        it { should be true }
      end
    end
  end
end
