control "SV-238308" do
  title "The Ubuntu operating system must record time stamps for audit records that can be mapped to
Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT). "
  desc "If time stamps are not consistently applied and there is no common time reference, it is
difficult to perform forensic analysis.

Time stamps generated by the operating system
include date and time. Time is commonly expressed in Coordinated Universal Time (UTC), a
modern continuation of Greenwich Mean Time (GMT), or local time with an offset from UTC."
  desc "default", "If time stamps are not consistently applied and there is no common time reference, it is
difficult to perform forensic analysis.

Time stamps generated by the operating system
include date and time. Time is commonly expressed in Coordinated Universal Time (UTC), a
modern continuation of Greenwich Mean Time (GMT), or local time with an offset from UTC."
  desc "check", "To verify the time zone is configured to use UTC or GMT, run the following command.

$
timedatectl status | grep -i \"time zone\"
Timezone: UTC (UTC, +0000)

If \"Timezone\" is not
set to UTC or GMT, this is a finding."
  desc "fix", "To configure the system time zone to use UTC or GMT, run the following command, replacing
[ZONE] with UTC or GMT:

$ sudo timedatectl set-timezone [ZONE]"
  impact 0.3
  tag severity: "low "
  tag gtitle: "SRG-OS-000359-GPOS-00146 "
  tag gid: "V-238308 "
  tag rid: "SV-238308r853426_rule "
  tag stig_id: "UBTU-20-010230 "
  tag fix_id: "F-41477r654098_fix "
  tag cci: ["CCI-001890"]
  tag nist: ["AU-8 b"]

  time_zone = command('timedatectl status | grep -i "time zone"').stdout.strip

  describe time_zone do
    it { should match 'UTC' }
  end

end