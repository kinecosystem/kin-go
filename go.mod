module github.com/kinecosystem/kin-go

go 1.13

require (
	github.com/golang/protobuf v1.5.0
	github.com/google/uuid v1.1.2
	github.com/kinecosystem/agora-api v0.26.0
	github.com/kinecosystem/agora-common v0.77.0
	github.com/kinecosystem/go v0.0.0-20191108204735-d6832148266e
	github.com/mattn/go-colorable v0.1.6 // indirect
	github.com/mr-tron/base58 v1.2.0
	github.com/pkg/errors v0.9.1
	github.com/stellar/go v0.0.0-20191211203732-552e507ffa37
	github.com/stretchr/objx v0.2.0 // indirect
	github.com/stretchr/testify v1.5.1
	golang.org/x/text v0.3.4 // indirect
	google.golang.org/genproto v0.0.0-20201204160425-06b3db808446 // indirect
	google.golang.org/grpc v1.37.0
)

// This dependency of stellar/go no longer exists; use a forked version of the repo instead.
replace bitbucket.org/ww/goautoneg => github.com/adjust/goautoneg v0.0.0-20150426214442-d788f35a0315

replace go.etcd.io/etcd v3.4.14+incompatible => go.etcd.io/etcd v0.0.0-20201125193152-8a03d2e9614b
