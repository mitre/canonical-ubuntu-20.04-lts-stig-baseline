control 'SV-238356' do
  title 'The Ubuntu operating system must, for networked systems, compare internal information system clocks at least every 24 hours with a server which is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.

Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).'
  desc 'check', 'If the system is not networked, this requirement is Not Applicable.

The system clock must be configured to compare the system clock at least every 24 hours to the authoritative time source.

Check the value of "maxpoll" in the "/etc/chrony/chrony.conf" file with the following command:

$ sudo  grep  maxpoll /etc/chrony/chrony.conf
server tick.usno.navy.mil iburst maxpoll 16

If the "maxpoll" option is set to a number greater than 16 or the line is commented out, this is a finding.

Verify that the "chrony.conf" file is configured to an authoritative DoD time source by running the following command:

$ grep -i server /etc/chrony/chrony.conf
server tick.usno.navy.mil iburst maxpoll 16
server tock.usno.navy.mil iburst maxpoll 16
server ntp2.usno.navy.mil iburst maxpoll 16

If the parameter "server" is not set, is not set to an authoritative DoD time source, or is commented out, this is a finding.'
  desc 'fix', 'If the system is not networked, this requirement is Not Applicable.

To configure the system clock to compare the system clock at least every 24 hours to the authoritative time source, edit the "/etc/chrony/chrony.conf" file. Add or correct the following lines, by replacing "[source]" in the following line with an authoritative DoD time source:

server [source] iburst maxpoll = 16

If the "chrony" service was running and the value of "maxpoll" or "server" was updated, the service must be restarted using the following command:

$ sudo systemctl restart chrony.service'
  impact 0.5
  tag check_id: 'C-41566r808490_chk'
  tag severity: 'medium'
  tag gid: 'V-238356'
  tag rid: 'SV-238356r1038944_rule'
  tag stig_id: 'UBTU-20-010435'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-41525r808491_fix'
  tag 'documentable'
  tag cci: ['CCI-001891', 'CCI-004923']
  tag nist: ['AU-8 (1) (a)', 'SC-45 (1) (a)']
  tag 'host'
  tag 'container'

  is_system_networked = input('is_system_networked')

  if is_system_networked
    chrony_conf_path = input('chrony_config_file')
    authoritative_timeservers = input('authoritative_timeservers')
    match_all_authoritative_timeservers_enabled = input('match_all_authoritative_timeservers_enabled')

    chrony_conf_exists = file(chrony_conf_path).exist?

    # `server` directives from the chrony config; compact drops the nil the
    # resource returns when none are configured (e.g. a pool-only or empty
    # config), so the maps below cannot raise.
    time_sources = chrony_conf_exists ? [chrony_conf(chrony_conf_path).server].flatten.compact : []

    # Map maxpoll values; chrony's default is 10 when maxpoll is not specified.
    max_poll_values = time_sources.map { |val|
      val.match?(/.*maxpoll.*/) ? val.gsub(/.*maxpoll\s+(\d+)(\s+.*|$)/, '\1').to_i : 10
    }

    # Map server hostnames only
    server_values = time_sources.map { |val|
      val.split.first
    }

    # Always emits a result: a missing config or a config with no `server`
    # directives is a finding, never a silent zero-result control (the bare
    # resource would report a skip on a missing file, hiding the finding).
    if chrony_conf_exists
      describe chrony_conf(chrony_conf_path) do
        its('server') { should_not be_nil }
      end
    else
      describe chrony_conf_path do
        it 'exists — chrony must be installed and configured with authoritative time sources' do
          expect(chrony_conf_exists).to be true
        end
      end
    end

    unless time_sources.empty?
      # Verify the chrony config lists authoritative DoD time source(s) with a
      # valid maxpoll (<= 16)
      describe 'chrony.conf' do
        if match_all_authoritative_timeservers_enabled
          it 'should include all specified valid timeservers' do
            expect(authoritative_timeservers.all? { |input|
                     server_values.include?(input) && max_poll_values[server_values.index(input)] <= 16
                   }).to be true
          end
        else
          it 'should include at least one valid timeserver' do
            expect(authoritative_timeservers.any? { |input|
              server_values.include?(input) && max_poll_values[server_values.index(input)] <= 16
            }).to be true
          end
        end
      end
    end
  else
    describe 'System is not networked' do
      skip 'This control is Not Applicable as the system is not networked'
    end
  end
end
