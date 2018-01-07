package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"

	log "github.com/Sirupsen/logrus"
	"github.com/totoview/spyglass/parsing"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var configFile = flag.String("c", "config.json", "Configuration file")

type config struct {
	Services []serviceConfig `json:"services"`
}

type serviceConfig struct {
	Name     string `json:"name"`
	Enable   bool   `json:"enable"`
	Codec    string `json:"codec"`
	Protocol string `json:"protocol"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
}

type parser struct {
	service      serviceConfig
	packetParser parsing.Parser
}

func (p parser) parse(ip *layers.IPv4, tcp *layers.TCP) {
	if len(tcp.Payload) == 0 {
		return
	}
	var hdr string
	// FIXME: check IP as well
	if int(tcp.SrcPort) == p.service.Port {
		hdr = fmt.Sprintf("%s:%d <-- %s", ip.DstIP, tcp.DstPort, color.YellowString(p.service.Name))
	} else if int(tcp.DstPort) == p.service.Port {
		hdr = fmt.Sprintf("%s:%d --> %s", ip.SrcIP, tcp.SrcPort, color.YellowString(p.service.Name))
	} else {
		return
	}
	fmt.Printf("%s\n", hdr)
	fmt.Printf("%s\n", hex.Dump(tcp.Payload))

}

type packetProcessor struct {
	device  pcap.Interface
	parsers []parser
}

func bind(dev pcap.Interface, svc serviceConfig) {
	fmt.Printf("Bind service %s (codec=%s, proto=%s, port=%d) to device %s at %s\n", color.YellowString(svc.Name), svc.Codec, svc.Protocol, svc.Port, color.YellowString(dev.Name), svc.IP)
	proc, ok := processors[dev.Name]
	if !ok {
		proc = &packetProcessor{}
		proc.device = dev
		processors[dev.Name] = proc
	}
	if pktParser, err := parsing.New(svc.Codec); err == nil {
		proc.parsers = append(proc.parsers, parser{service: svc, packetParser: pktParser})
	} else {
		log.Errorf("Invalid codec %s", svc.Codec)
	}
}

var processors = make(map[string]*packetProcessor)

func main() {

	flag.Parse()

	raw, err := ioutil.ReadFile(*configFile)
	if err != nil {
		panic(err)
	}

	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		panic(err)
	}

	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	for _, dev := range devices {
		for _, addr := range dev.Addresses {
			if addr.IP != nil {
				for _, svc := range cfg.Services {
					if svc.Enable && svc.IP == addr.IP.String() {
						bind(dev, svc)
					}
				}
			}
		}
	}

	var snapshotLen int32 = 1 << 16
	promiscuous := false

	for dev, proc := range processors {
		// open device
		handle, err := pcap.OpenLive(dev, snapshotLen, promiscuous, pcap.BlockForever)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()

		packageSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packageSource.Packets() {
			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
					ip, _ := ipLayer.(*layers.IPv4)
					tcp, _ := tcpLayer.(*layers.TCP)
					for _, p := range proc.parsers {
						p.parse(ip, tcp)
					}
				}
			}
		}
	}
}
