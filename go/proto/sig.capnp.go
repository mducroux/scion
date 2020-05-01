// Code generated by capnpc-go. DO NOT EDIT.

package proto

import (
	strconv "strconv"
	capnp "zombiezen.com/go/capnproto2"
	text "zombiezen.com/go/capnproto2/encoding/text"
	schemas "zombiezen.com/go/capnproto2/schemas"
)

type SIGCtrl struct{ capnp.Struct }
type SIGCtrl_Which uint16

const (
	SIGCtrl_Which_unset   SIGCtrl_Which = 0
	SIGCtrl_Which_pollReq SIGCtrl_Which = 1
	SIGCtrl_Which_pollRep SIGCtrl_Which = 2
)

func (w SIGCtrl_Which) String() string {
	const s = "unsetpollReqpollRep"
	switch w {
	case SIGCtrl_Which_unset:
		return s[0:5]
	case SIGCtrl_Which_pollReq:
		return s[5:12]
	case SIGCtrl_Which_pollRep:
		return s[12:19]

	}
	return "SIGCtrl_Which(" + strconv.FormatUint(uint64(w), 10) + ")"
}

// SIGCtrl_TypeID is the unique identifier for the type SIGCtrl.
const SIGCtrl_TypeID = 0xe15e242973323d08

func NewSIGCtrl(s *capnp.Segment) (SIGCtrl, error) {
	st, err := capnp.NewStruct(s, capnp.ObjectSize{DataSize: 16, PointerCount: 1})
	return SIGCtrl{st}, err
}

func NewRootSIGCtrl(s *capnp.Segment) (SIGCtrl, error) {
	st, err := capnp.NewRootStruct(s, capnp.ObjectSize{DataSize: 16, PointerCount: 1})
	return SIGCtrl{st}, err
}

func ReadRootSIGCtrl(msg *capnp.Message) (SIGCtrl, error) {
	root, err := msg.RootPtr()
	return SIGCtrl{root.Struct()}, err
}

func (s SIGCtrl) String() string {
	str, _ := text.Marshal(0xe15e242973323d08, s.Struct)
	return str
}

func (s SIGCtrl) Which() SIGCtrl_Which {
	return SIGCtrl_Which(s.Struct.Uint16(8))
}
func (s SIGCtrl) Id() uint64 {
	return s.Struct.Uint64(0)
}

func (s SIGCtrl) SetId(v uint64) {
	s.Struct.SetUint64(0, v)
}

func (s SIGCtrl) SetUnset() {
	s.Struct.SetUint16(8, 0)

}

func (s SIGCtrl) PollReq() (SIGPoll, error) {
	if s.Struct.Uint16(8) != 1 {
		panic("Which() != pollReq")
	}
	p, err := s.Struct.Ptr(0)
	return SIGPoll{Struct: p.Struct()}, err
}

func (s SIGCtrl) HasPollReq() bool {
	if s.Struct.Uint16(8) != 1 {
		return false
	}
	p, err := s.Struct.Ptr(0)
	return p.IsValid() || err != nil
}

func (s SIGCtrl) SetPollReq(v SIGPoll) error {
	s.Struct.SetUint16(8, 1)
	return s.Struct.SetPtr(0, v.Struct.ToPtr())
}

// NewPollReq sets the pollReq field to a newly
// allocated SIGPoll struct, preferring placement in s's segment.
func (s SIGCtrl) NewPollReq() (SIGPoll, error) {
	s.Struct.SetUint16(8, 1)
	ss, err := NewSIGPoll(s.Struct.Segment())
	if err != nil {
		return SIGPoll{}, err
	}
	err = s.Struct.SetPtr(0, ss.Struct.ToPtr())
	return ss, err
}

func (s SIGCtrl) PollRep() (SIGPoll, error) {
	if s.Struct.Uint16(8) != 2 {
		panic("Which() != pollRep")
	}
	p, err := s.Struct.Ptr(0)
	return SIGPoll{Struct: p.Struct()}, err
}

func (s SIGCtrl) HasPollRep() bool {
	if s.Struct.Uint16(8) != 2 {
		return false
	}
	p, err := s.Struct.Ptr(0)
	return p.IsValid() || err != nil
}

func (s SIGCtrl) SetPollRep(v SIGPoll) error {
	s.Struct.SetUint16(8, 2)
	return s.Struct.SetPtr(0, v.Struct.ToPtr())
}

// NewPollRep sets the pollRep field to a newly
// allocated SIGPoll struct, preferring placement in s's segment.
func (s SIGCtrl) NewPollRep() (SIGPoll, error) {
	s.Struct.SetUint16(8, 2)
	ss, err := NewSIGPoll(s.Struct.Segment())
	if err != nil {
		return SIGPoll{}, err
	}
	err = s.Struct.SetPtr(0, ss.Struct.ToPtr())
	return ss, err
}

// SIGCtrl_List is a list of SIGCtrl.
type SIGCtrl_List struct{ capnp.List }

// NewSIGCtrl creates a new list of SIGCtrl.
func NewSIGCtrl_List(s *capnp.Segment, sz int32) (SIGCtrl_List, error) {
	l, err := capnp.NewCompositeList(s, capnp.ObjectSize{DataSize: 16, PointerCount: 1}, sz)
	return SIGCtrl_List{l}, err
}

func (s SIGCtrl_List) At(i int) SIGCtrl { return SIGCtrl{s.List.Struct(i)} }

func (s SIGCtrl_List) Set(i int, v SIGCtrl) error { return s.List.SetStruct(i, v.Struct) }

func (s SIGCtrl_List) String() string {
	str, _ := text.MarshalList(0xe15e242973323d08, s.List)
	return str
}

// SIGCtrl_Promise is a wrapper for a SIGCtrl promised by a client call.
type SIGCtrl_Promise struct{ *capnp.Pipeline }

func (p SIGCtrl_Promise) Struct() (SIGCtrl, error) {
	s, err := p.Pipeline.Struct()
	return SIGCtrl{s}, err
}

func (p SIGCtrl_Promise) PollReq() SIGPoll_Promise {
	return SIGPoll_Promise{Pipeline: p.Pipeline.GetPipeline(0)}
}

func (p SIGCtrl_Promise) PollRep() SIGPoll_Promise {
	return SIGPoll_Promise{Pipeline: p.Pipeline.GetPipeline(0)}
}

type SIGPoll struct{ capnp.Struct }

// SIGPoll_TypeID is the unique identifier for the type SIGPoll.
const SIGPoll_TypeID = 0x9ad73a0235a46141

func NewSIGPoll(s *capnp.Segment) (SIGPoll, error) {
	st, err := capnp.NewStruct(s, capnp.ObjectSize{DataSize: 8, PointerCount: 1})
	return SIGPoll{st}, err
}

func NewRootSIGPoll(s *capnp.Segment) (SIGPoll, error) {
	st, err := capnp.NewRootStruct(s, capnp.ObjectSize{DataSize: 8, PointerCount: 1})
	return SIGPoll{st}, err
}

func ReadRootSIGPoll(msg *capnp.Message) (SIGPoll, error) {
	root, err := msg.RootPtr()
	return SIGPoll{root.Struct()}, err
}

func (s SIGPoll) String() string {
	str, _ := text.Marshal(0x9ad73a0235a46141, s.Struct)
	return str
}

func (s SIGPoll) Addr() (SIGAddr, error) {
	p, err := s.Struct.Ptr(0)
	return SIGAddr{Struct: p.Struct()}, err
}

func (s SIGPoll) HasAddr() bool {
	p, err := s.Struct.Ptr(0)
	return p.IsValid() || err != nil
}

func (s SIGPoll) SetAddr(v SIGAddr) error {
	return s.Struct.SetPtr(0, v.Struct.ToPtr())
}

// NewAddr sets the addr field to a newly
// allocated SIGAddr struct, preferring placement in s's segment.
func (s SIGPoll) NewAddr() (SIGAddr, error) {
	ss, err := NewSIGAddr(s.Struct.Segment())
	if err != nil {
		return SIGAddr{}, err
	}
	err = s.Struct.SetPtr(0, ss.Struct.ToPtr())
	return ss, err
}

func (s SIGPoll) Session() uint8 {
	return s.Struct.Uint8(0)
}

func (s SIGPoll) SetSession(v uint8) {
	s.Struct.SetUint8(0, v)
}

// SIGPoll_List is a list of SIGPoll.
type SIGPoll_List struct{ capnp.List }

// NewSIGPoll creates a new list of SIGPoll.
func NewSIGPoll_List(s *capnp.Segment, sz int32) (SIGPoll_List, error) {
	l, err := capnp.NewCompositeList(s, capnp.ObjectSize{DataSize: 8, PointerCount: 1}, sz)
	return SIGPoll_List{l}, err
}

func (s SIGPoll_List) At(i int) SIGPoll { return SIGPoll{s.List.Struct(i)} }

func (s SIGPoll_List) Set(i int, v SIGPoll) error { return s.List.SetStruct(i, v.Struct) }

func (s SIGPoll_List) String() string {
	str, _ := text.MarshalList(0x9ad73a0235a46141, s.List)
	return str
}

// SIGPoll_Promise is a wrapper for a SIGPoll promised by a client call.
type SIGPoll_Promise struct{ *capnp.Pipeline }

func (p SIGPoll_Promise) Struct() (SIGPoll, error) {
	s, err := p.Pipeline.Struct()
	return SIGPoll{s}, err
}

func (p SIGPoll_Promise) Addr() SIGAddr_Promise {
	return SIGAddr_Promise{Pipeline: p.Pipeline.GetPipeline(0)}
}

type SIGAddr struct{ capnp.Struct }

// SIGAddr_TypeID is the unique identifier for the type SIGAddr.
const SIGAddr_TypeID = 0xddf1fce11d9b0028

func NewSIGAddr(s *capnp.Segment) (SIGAddr, error) {
	st, err := capnp.NewStruct(s, capnp.ObjectSize{DataSize: 0, PointerCount: 2})
	return SIGAddr{st}, err
}

func NewRootSIGAddr(s *capnp.Segment) (SIGAddr, error) {
	st, err := capnp.NewRootStruct(s, capnp.ObjectSize{DataSize: 0, PointerCount: 2})
	return SIGAddr{st}, err
}

func ReadRootSIGAddr(msg *capnp.Message) (SIGAddr, error) {
	root, err := msg.RootPtr()
	return SIGAddr{root.Struct()}, err
}

func (s SIGAddr) String() string {
	str, _ := text.Marshal(0xddf1fce11d9b0028, s.Struct)
	return str
}

func (s SIGAddr) Ctrl() (HostInfo, error) {
	p, err := s.Struct.Ptr(0)
	return HostInfo{Struct: p.Struct()}, err
}

func (s SIGAddr) HasCtrl() bool {
	p, err := s.Struct.Ptr(0)
	return p.IsValid() || err != nil
}

func (s SIGAddr) SetCtrl(v HostInfo) error {
	return s.Struct.SetPtr(0, v.Struct.ToPtr())
}

// NewCtrl sets the ctrl field to a newly
// allocated HostInfo struct, preferring placement in s's segment.
func (s SIGAddr) NewCtrl() (HostInfo, error) {
	ss, err := NewHostInfo(s.Struct.Segment())
	if err != nil {
		return HostInfo{}, err
	}
	err = s.Struct.SetPtr(0, ss.Struct.ToPtr())
	return ss, err
}

func (s SIGAddr) Data() (HostInfo, error) {
	p, err := s.Struct.Ptr(1)
	return HostInfo{Struct: p.Struct()}, err
}

func (s SIGAddr) HasData() bool {
	p, err := s.Struct.Ptr(1)
	return p.IsValid() || err != nil
}

func (s SIGAddr) SetData(v HostInfo) error {
	return s.Struct.SetPtr(1, v.Struct.ToPtr())
}

// NewData sets the data field to a newly
// allocated HostInfo struct, preferring placement in s's segment.
func (s SIGAddr) NewData() (HostInfo, error) {
	ss, err := NewHostInfo(s.Struct.Segment())
	if err != nil {
		return HostInfo{}, err
	}
	err = s.Struct.SetPtr(1, ss.Struct.ToPtr())
	return ss, err
}

// SIGAddr_List is a list of SIGAddr.
type SIGAddr_List struct{ capnp.List }

// NewSIGAddr creates a new list of SIGAddr.
func NewSIGAddr_List(s *capnp.Segment, sz int32) (SIGAddr_List, error) {
	l, err := capnp.NewCompositeList(s, capnp.ObjectSize{DataSize: 0, PointerCount: 2}, sz)
	return SIGAddr_List{l}, err
}

func (s SIGAddr_List) At(i int) SIGAddr { return SIGAddr{s.List.Struct(i)} }

func (s SIGAddr_List) Set(i int, v SIGAddr) error { return s.List.SetStruct(i, v.Struct) }

func (s SIGAddr_List) String() string {
	str, _ := text.MarshalList(0xddf1fce11d9b0028, s.List)
	return str
}

// SIGAddr_Promise is a wrapper for a SIGAddr promised by a client call.
type SIGAddr_Promise struct{ *capnp.Pipeline }

func (p SIGAddr_Promise) Struct() (SIGAddr, error) {
	s, err := p.Pipeline.Struct()
	return SIGAddr{s}, err
}

func (p SIGAddr_Promise) Ctrl() HostInfo_Promise {
	return HostInfo_Promise{Pipeline: p.Pipeline.GetPipeline(0)}
}

func (p SIGAddr_Promise) Data() HostInfo_Promise {
	return HostInfo_Promise{Pipeline: p.Pipeline.GetPipeline(1)}
}

const schema_8273379c3e06a721 = "x\xdat\x91Ok\x1aQ\x14\xc5\xefy\xcf\x19\xffP" +
	"q\x06]\x09\xa5-X\xaa\x82\xa5J\xa5 \xb4\xd4\x96" +
	"R\xb2\xf3%\xdb\x1028C\x1c\x98\xe883\xe2R" +
	"\xc8G0\xbb$\xcb@6Y\xe5{d\x91E\xc8*" +
	"\x0bWYg\x1f\xf3\xc2c\x12\x95HV\x17\xce\xb9\xdc" +
	"\xdf;\xef\x18\xe7\xbfY]\xcb\x81H\xbc\xd3t\xd9\xb6" +
	"N\x9b\xacusD\"\x03\xc8Og\xfa\xaf\x93\x1f\xe1" +
	"\x01iH\x12\x99\xfbSs\xa4\xe6pL\x98\x97\x8f\xdf" +
	"\xcf\x1e\xeeo\xcd\xcc\xea\x1aS\xf6\xe5\xd4\xbcV\xf3j" +
	"L\x90\xa9\x9f\x8d\xb0R\xda\x99\xa9\x83l\xb9\xf9\x0fI" +
	"\x8eD\xbe\x86i\xbe\xa9n\xe7\xeb\xb8#\xc8\xd0\xdd\xfb" +
	"\xda\xb5\xfc>\xfc\xd6\xd6\xc6\xff\xce\xc0\x83\xd7\x01D\x8a" +
	"'\x88\x12 2+U\"Q\xe2\x10\xdf\x18\x80\x02\x94" +
	"V\xfbC$\xca\x1c\xe2;C\xce\xb2\xed\x00\xc6\xcb\xeb" +
	"\x080\x08\x93\xd0\x09Cw\xd0\x87N\x0c\xfa\x1a\xa6m" +
	"\xdb\x08\xde\xc6\x98\x0bNu\x85\xd3\x8d\x02\x0f\x86\xfc\xf8" +
	"\xf9p\xac})^PL\xca\xd9Vd\xad\xcb\xaf\x80" +
	"\x7f\xa3 \xcee,\x80V\x91Hls\x88\x1eC\x16" +
	"R\xc6D\xa7A$v9\x84\xc7\x90e\x8f\xb2\x00F" +
	"d\xba*\xaf\xcd!|\x86,\x9f\xcb\x02\xb8*G\xa9" +
	"=\x0e\x111p\xd7F\x9a\x18\xd2\x84\x0f\xa3~\xe8D" +
	"\xa4O\xfc\x81\xe7m:C\x18\xcb\x8e\x9f\x7f'v\xfc" +
	"u\xe7)\x00\x00\xff\xff\x12\xacx\x8f"

func init() {
	schemas.Register(schema_8273379c3e06a721,
		0x9ad73a0235a46141,
		0xddf1fce11d9b0028,
		0xe15e242973323d08)
}
