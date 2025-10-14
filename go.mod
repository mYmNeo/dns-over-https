module github.com/m13253/dns-over-https/v2

go 1.26.0

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/OneYX/v2ray-core v0.0.0
	github.com/coreos/go-iptables v0.8.0
	github.com/gorilla/handlers v1.5.2
	github.com/infobloxopen/go-trees v0.0.0-20221216143356-66ceba885ebc
	github.com/miekg/dns v1.1.73
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/net v0.61.0
)

require (
	github.com/felixge/httpsnoop v1.1.0 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

replace github.com/OneYX/v2ray-core => ./staging/github.com/OneYX/v2ray-core
