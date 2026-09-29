module github.com/bakhod1r/ipx/integrations/geoip

go 1.25.0

require github.com/maxmind/mmdbwriter v1.2.0

require (
	github.com/bakhod1r/ipx v0.5.0
	github.com/oschwald/maxminddb-golang/v2 v2.6.0
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/sys v0.47.0 // indirect
)

replace github.com/bakhod1r/ipx => ../..
