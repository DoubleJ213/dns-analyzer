package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var config struct {
	argInterface string
	argFile      string
	argConfigDir string
	argVmFile    string
	//resync period of informer
	argPeriod string
}

type Capture struct {
	SrcApp   string
	Src      string
	SrcPort  string
	Record   string
	AnswerIp string
	Packet   *gopacket.Packet
}

func getUserInput() {
	flag.StringVar(&config.argInterface, "i", "", "Interface Name")
	flag.StringVar(&config.argFile, "r", "", "Offline capture file to be read")
	flag.StringVar(&config.argConfigDir, "d", "", "Directory of k8s certification documents")
	flag.StringVar(&config.argVmFile, "f", "", "File of vm's datum")
	//flag.StringVar(&config.argPattern, "s", "", "Pattern matching")
	//flag.StringVar(&config.argPeriod, "p", "", "Results response period")
	flag.Parse()
	unProcessedCount := flag.NArg()
	if unProcessedCount == 0 {
		return
	}
	return
}

func preProcessInterface() bool {
	devices, _ := pcap.FindAllDevs()

	// Check if user-defined interface exist
	for _, device := range devices {
		if len(config.argInterface) == 0 {
			config.argInterface = device.Name
			return true
		}
		if device.Name == config.argInterface {
			return true
		}
	}
	return false
}

func liveCapture(db *MemDataBuilder, ifaceName string) {
	handle, err := pcap.OpenLive(ifaceName, 65535, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	//if len(expr) > 0 {
	//	if err := handle.SetBPFFilter(expr); err != nil {
	//		panic(err)
	//	}
	//}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("Live Capture Started...")

	for packet := range packetSource.Packets() {
		got := &Capture{}
		got.Packet = &packet
		if got.pipeline(udp, dns, ipv4) {
			go func(got *Capture) {
				//协程中处理，之前考虑直接调cmdb接口解析vm机器数据
				//防止其他类型的DataBuilder处理比较慢,导致packet消费太慢，协程没删
				db.Analyzer(got)
			}(got)
		}
	}
}

func udp(got *Capture) bool {
	packet := *got.Packet
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udpp, _ := udpLayer.(*layers.UDP)
		got.SrcPort = fmt.Sprintf("%s", udpp.DstPort)
		return true
	}
	return false
}

func dns(got *Capture) bool {
	packet := *got.Packet
	if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		questions := packet.Layer(layers.LayerTypeDNS).(*layers.DNS).Questions
		if len(questions) != 1 {
			return false
		}
		answers := packet.Layer(layers.LayerTypeDNS).(*layers.DNS).Answers

		if len(answers) == 0 {
			return false
		}
		var answer []byte
		var answerIp string
		for _, a := range answers {
			if a.DataLength == 0 {
				continue
			}
			answer = a.Name
			answerIp = fmt.Sprintf("%s", a.IP)
		}

		got.Record = fmt.Sprintf("%s", answer)
		got.AnswerIp = fmt.Sprintf("%s", answerIp)
		return true
	}
	return false
}

func ipv4(got *Capture) bool {
	packet := *got.Packet
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		got.Src = fmt.Sprintf("%s", ip.DstIP)
		return true
	}
	return false
}

type PipeFunc func(*Capture) bool

func (got *Capture) pipeline(pipeFns ...PipeFunc) bool {
	var status bool
	for i := range pipeFns {
		if !pipeFns[i](got) {
			break
		}
	}
	return status
}

func offlineCapture(filename string) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		panic(err)
	}
	//if len(expr) > 0 {
	//	if err := handle.SetBPFFilter(expr); err != nil {
	//		panic(err)
	//	}
	//}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("File Reading Started...")
	_ = packetSource

}

func main() {
	getUserInput()
	var configPath string
	var vmDatafile string

	if config.argConfigDir == "" {
		//存放k8s认证文件的目录，不递归查询子目录的文件
		configPath = "/opt/dns-an/config"
	} else {
		configPath = config.argConfigDir
	}

	if config.argVmFile == "" {
		//cmdb捞取的数据文件
		vmDatafile = "/opt/dns-an/data.txt"
	} else {
		vmDatafile = config.argVmFile
	}

	db := &MemDataBuilder{}
	db.Init().WithVm(vmDatafile).WithPod(configPath)

	if !preProcessInterface() {
		fmt.Println("invalid interface (check arguments)")
		return
	}

	if len(config.argFile) > 0 {
		// offline
		offlineCapture(config.argFile)
	} else {
		// live packet capture
		liveCapture(db, config.argInterface)
	}
}
