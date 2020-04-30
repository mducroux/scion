package main

import (
	"encoding/json"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/seghandler"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/proto"
	"io/ioutil"
	"os"
)

type Segments struct {
	Segments []Segment `json:"segments"`
}

type Segment struct {
	SrcISD    uint16    `json:"srcISD"`
	SrcAS     string    `json:"srcAS"`
	DstISD    uint16    `json:"dstISD"`
	DstAS     string    `json:"dstAS"`
	NbHops    uint8     `json:"nb_hops"`
	Latency   uint32    `json:"latency"`
	Bandwidth uint64    `json:"bandwidth"`
	ASEntries []ASEntry `json:"ASentries"`
}

type ASEntry struct {
	IA        string  `json:"IA"`
	Latitude  float32 `json:"latitude"`
	Longitude float32 `json:"longitude"`
	Hop      Hop     `json:"hop"`
}

type Hop struct {
	InIA  string `json:"IA"`
	InIF  uint64 `json:"InIF"`
	OutIA string `json:"OutIA"`
	OutIF uint64 `json:"OutIF"`
}

func main() {
	//_, cancelF := context.WithTimeout(context.Background(), 5*time.Second)
	//defer cancelF()

	segmentsFile, err := os.Open("segments.txt")
	if err != nil {
		os.Exit(1)
	}
	defer segmentsFile.Close()

	byteSegments, _ := ioutil.ReadAll(segmentsFile)
	var segments Segments
	if err := json.Unmarshal(byteSegments, &segments); err != nil {
		os.Exit(1)
	}

	var toRegister []*seghandler.SegWithHP

	for i := 0; i < len(segments.Segments); i++ {
		scionSegment := createScionSegment(segments.Segments[i])
		toRegister = append(toRegister, scionSegment)
	}

	//pathDB := ???
	//SegStore := &seghandler.DefaultStorage{PathDB: pathDB}
	//SegStore.StoreSegs(ctx, toRegister)
}

func createScionSegment(segment Segment) *seghandler.SegWithHP {
	var scionSegment *seg.PathSegment
	infoField := &spath.InfoField{
		ConsDir:  false,
		Shortcut: false,
		Peer:     false,
		TsInt:    0,
		ISD:      segment.DstISD,
		Hops:     segment.NbHops,
	}
	scionSegment, _ = seg.NewSeg(infoField)
	for i := 0; i < len(segment.ASEntries); i++ {
		asEntry := createScionASEntry(segment.ASEntries[i])
		err := scionSegment.AddASEntry(&asEntry, infra.NullSigner)
		if err != nil {
			os.Exit(1)
		}
	}
	segmentWithHP := &seghandler.SegWithHP{
		Seg: &seg.Meta{Type: proto.PathSegTypeFromString("core"), Segment: scionSegment},
	}
	return segmentWithHP
}

func createScionASEntry(asEntry ASEntry) seg.ASEntry {
	hopEntry := &seg.HopEntry{
		RawInIA:     IAIntFromString(asEntry.Hop.InIA),
		RemoteInIF:  common.IFIDType(asEntry.Hop.InIF),
		InMTU:       1500,
		RawOutIA:    IAIntFromString(asEntry.Hop.OutIA),
		RemoteOutIF: common.IFIDType(asEntry.Hop.OutIF),
		RawHopField: nil,
	}

	scionASEntry := seg.ASEntry{
		RawIA:      IAIntFromString(asEntry.IA),
		TrcVer:     scrypto.LatestVer,
		CertVer:    scrypto.LatestVer,
		IfIDSize:   nil,
		HopEntries: []*seg.HopEntry{hopEntry},
		MTU:        1500,
		Exts:       nil,
	}
	return scionASEntry
}

func IAIntFromString(iaString string) addr.IAInt {
	asEntryIA, err := addr.IAFromString(iaString)
	if err != nil {
		os.Exit(1)
	}
	return asEntryIA.IAInt()
}
