control 'SV-238207' do
  title 'The Ubuntu operating system must automatically terminate a user session after inactivity timeouts have expired.'
  desc "Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific operating system functionality where the system owner, data owner, or organization requires additional assurance."
  desc 'check', 'Verify the operating system automatically terminates a user session after inactivity timeouts have expired.

Check that the "TMOUT" environment variable is set in the "/etc/bash.bashrc" file or in any file inside the "/etc/profile.d/" directory by performing the following command:

$ sudo grep -E "\\bTMOUT=[0-9]+" /etc/bash.bashrc /etc/profile.d/*

TMOUT=600

If "TMOUT" is not set, or if the value is "0" or is commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to automatically terminate a user session after inactivity timeouts have expired or at shutdown.

Create the file "/etc/profile.d/99-terminal_tmout.sh" file if it does not exist.

Modify or append the following line in the "/etc/profile.d/99-terminal_tmout.sh " file:

TMOUT=600

This will set a timeout value of 10 minutes for all future sessions.

To set the timeout for the current sessions, execute the following command over the terminal session:

$ export TMOUT=600'
  impact 0.5
  tag check_id: 'C-41417r1069085_chk'
  tag severity: 'medium'
  tag gid: 'V-238207'
  tag rid: 'SV-238207r1069086_rule'
  tag stig_id: 'UBTU-20-010013'
  tag gtitle: 'SRG-OS-000279-GPOS-00109'
  tag fix_id: 'F-41376r653795_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  expected_timeout = input('system_activity_timeout')

  # Grab all TMOUT lines from bashrc and profile.d scripts, ignoring comments
  tmout_lines = command(
    'sudo grep -E "^[^#]*\\bTMOUT=[0-9]+" /etc/bash.bashrc /etc/profile.d/* 2>/dev/null'
  ).stdout.lines.map(&:strip)

  describe 'TMOUT configuration' do
    it 'should be set in at least one system-wide profile file' do
      expect(tmout_lines).not_to be_empty, 'No TMOUT value set in any system-wide profile file'
    end

    it 'should not set TMOUT=0 in any file' do
      insecure = tmout_lines.grep(/TMOUT\s*=\s*0/i)
      expect(insecure).to be_empty, "Insecure TMOUT=0 found in: #{insecure.join(', ')}"
    end

    it "should terminate sessions after no more than #{expected_timeout} seconds" do
      values = tmout_lines.map { |l| l.match(/TMOUT\s*=\s*(\d+)/i)&.captures&.first }.compact.map(&:to_i)
      expect(values).not_to be_empty
      over = values.select { |v| v > expected_timeout }
      expect(over).to be_empty, "TMOUT values exceeding #{expected_timeout} found: #{over.join(', ')}"
    end
  end
end
