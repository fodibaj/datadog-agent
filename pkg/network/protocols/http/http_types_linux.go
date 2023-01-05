// Code generated by cmd/cgo -godefs; DO NOT EDIT.
// cgo -godefs -- -I ../../ebpf/c -I ../../../ebpf/c -fsigned-char http_types.go

package http

type httpConnTuple struct {
	Saddr_h  uint64
	Saddr_l  uint64
	Daddr_h  uint64
	Daddr_l  uint64
	Sport    uint16
	Dport    uint16
	Netns    uint32
	Pid      uint32
	Metadata uint32
}
type sslSock struct {
	Tup       httpConnTuple
	Fd        uint32
	Pad_cgo_0 [4]byte
}
type sslReadArgs struct {
	Ctx *byte
	Buf *byte
}

type ebpfHttpTx struct {
	Tup                  httpConnTuple
	Request_started      uint64
	Request_method       uint8
	Response_status_code uint16
	Response_last_seen   uint64
	Request_fragment     [160]byte
	Owned_by_src_port    uint16
	Tcp_seq              uint32
	Tags                 uint64
}

type libPath struct {
	Pid uint32
	Len uint32
	Buf [120]byte
}

type ProtocolType uint8

const (
	ProtocolUnknown ProtocolType = 0x1
	ProtocolHTTP    ProtocolType = 0x2
	ProtocolHTTP2   ProtocolType = 0x3
	ProtocolTLS     ProtocolType = 0x4
	ProtocolMONGO   ProtocolType = 0x6
	ProtocolAMQP    ProtocolType = 0x8
	ProtocolRedis   ProtocolType = 0x9
	ProtocolMax     ProtocolType = 0xa
)

const (
	HTTPBufferSize = 0xa0

	libPathMaxSize = 0x78
)

type ConnTag = uint64

const (
	GnuTLS  ConnTag = 0x1
	OpenSSL ConnTag = 0x2
	Go      ConnTag = 0x4
)

var (
	StaticTags = map[ConnTag]string{
		GnuTLS:  "tls.library:gnutls",
		OpenSSL: "tls.library:openssl",
		Go:      "tls.library:go",
	}
)
