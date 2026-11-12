# AEGEX - Zeek site script, passed to zeek as an extra script (the default base scripts, which produce conn.log, are still loaded).
# JSON output is required: the AEGEX pipeline parses conn.log and notice.log as JSON lines.
redef LogAscii::use_json = T;

# Port-scan / address-scan detection -> notice.log (policy script shipped with Zeek).
@load misc/scan
