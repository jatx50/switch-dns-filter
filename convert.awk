# Convert an Atmosphere hosts file to AdGuard Home rules
# for the persistent client 'NSwitch cfw'.
# On a line that fails a check, stop with exit status 1.
function fail(msg) {
  print "convert.awk: line " NR ": " msg > "/dev/stderr"
  exit 1
}
{
  sub(/\r$/, "")
  sub(/#.*/, "")
  if (NF == 0) next
  if (NF < 2) fail("no host field")
  ip = $1
  if (ip !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) fail("bad IP: " ip)
  split(ip, o, ".")
  for (j = 1; j <= 4; j++)
    if (o[j] + 0 > 255) fail("bad IP: " ip)
  for (i = 2; i <= NF; i++) {
    h = $i
    if (h !~ /^\*?[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]+$/)
      fail("bad host: " h)
    if (h !~ /nintendo/) fail("host without nintendo: " h)
    if (ip == "127.0.0.1" || ip == "0.0.0.0")
      print h "^$client='NSwitch cfw'"
    else
      print h "^$client='NSwitch cfw',dnsrewrite=NOERROR;A;" ip
  }
}
