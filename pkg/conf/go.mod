module github.com/DataDog/datadog-agent/pkg/conf

go 1.20

replace (
	github.com/DataDog/datadog-agent/pkg/util/log => ../util/log/
	github.com/DataDog/datadog-agent/pkg/util/system/socket => ../util/system/socket
)

require (
	github.com/DataDog/datadog-agent/pkg/util/log v0.0.0-00010101000000-000000000000
	github.com/DataDog/datadog-agent/pkg/util/system/socket v0.0.0-00010101000000-000000000000
	github.com/DataDog/viper v1.12.0
	github.com/spf13/afero v1.9.5
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.8.4
)

require (
	github.com/DataDog/datadog-agent/pkg/util/scrubber v0.48.0-rc.2 // indirect
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/cihub/seelog v0.0.0-20170130134532-f561c5e57575 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.4.7 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/magiconair/properties v1.8.1 // indirect
	github.com/mitchellh/mapstructure v1.1.2 // indirect
	github.com/pelletier/go-toml v1.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spf13/cast v1.3.0 // indirect
	github.com/spf13/jwalterweatherman v1.0.0 // indirect
	golang.org/x/mod v0.8.0 // indirect
	golang.org/x/sys v0.5.0 // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/tools v0.6.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
