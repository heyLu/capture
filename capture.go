package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var localPortMin, localPortMax uint16 = 32768, 60999
var pidRE = regexp.MustCompile(`^[0-9]+$`)

var config struct {
	file  string
	iface string
}

type stat struct {
	packetsRx int
	packetsTx int
	bytesRx   int
	bytesTx   int
}

var stats = map[string]*stat{}

var addrLookupCache = map[string]string{}

func main() {
	flag.StringVar(&config.file, "f", "", ".pcap file to read from")
	flag.StringVar(&config.iface, "i", "lo", "interface to read from")
	flag.Parse()

	var handle *pcap.Handle
	var err error
	if config.file != "" {
		handle, err = pcap.OpenOffline(config.file)
	} else {
		handle, err = pcap.OpenLive(config.iface, 1600, true, pcap.BlockForever)
	}
	if err != nil {
		log.Fatal("pcap open:", err)
	}

	c := 0
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		c++

		w := len(strconv.Itoa(c))
		fmt.Printf("%s%d\n", strings.Repeat("-", 60-w), c)

		layerNames := make([]string, len(packet.Layers()))
		for i, layer := range packet.Layers() {
			layerNames[i] = layer.LayerType().String()
		}
		fmt.Println(layerNames)

		var srcIP net.IP
		var dstIP net.IP

		if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
			ipv4, _ := ipv4Layer.(*layers.IPv4)
			srcIP = ipv4.SrcIP
			dstIP = ipv4.DstIP
		}
		if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
			ipv6, _ := ipv6Layer.(*layers.IPv6)
			srcIP = ipv6.SrcIP
			dstIP = ipv6.DstIP
		}
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			var typ string
			switch {
			case tcp.FIN:
				typ = "FIN"
			case tcp.SYN:
				typ = "SYN"
			case tcp.RST:
				typ = "RST"
			case tcp.PSH:
				typ = "PSH"
			case tcp.ACK:
				typ = "ACK"
			case tcp.URG:
				typ = "URG"
			case tcp.ECE:
				typ = "ECE"
			case tcp.CWR:
				typ = "CWR"
			case tcp.NS:
				typ = "NS"
			default:
				typ = "?"
			}
			fmt.Printf("tcp %s (%s:%d -> %s:%d)\n", typ, srcIP, tcp.SrcPort, dstIP, tcp.DstPort)
			printPort("/proc/net/tcp", uint16(tcp.SrcPort))
			printPort("/proc/net/tcp", uint16(tcp.DstPort))

			if tcp.PSH || len(tcp.Payload) > 0 {
				fmt.Printf("  payload (%d bytes)\n", len(tcp.Payload))
			}

			var remoteIP net.IP
			var remotePort layers.TCPPort
			var isRx bool
			if tcp.SrcPort < tcp.DstPort {
				isRx = true
				remoteIP = srcIP
				remotePort = tcp.SrcPort
			} else {
				remoteIP = dstIP
				remotePort = tcp.DstPort
				isRx = false
			}
			dst := fmt.Sprintf("%s:%d", remoteIP, remotePort)
			if stats[dst] == nil {
				stats[dst] = &stat{}
			}
			stat := stats[dst]
			if isRx {
				stat.packetsRx++
				stat.bytesRx += len(tcp.Payload)
			} else {
				stat.packetsTx++
				stat.bytesTx += len(tcp.Payload)
			}
		}

		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			fmt.Printf("udp (%s:%d -> %s:%d)\n", srcIP, udp.SrcPort, dstIP, udp.DstPort)
			printPort("/proc/net/udp", uint16(udp.SrcPort))
			printPort("/proc/net/udp", uint16(udp.DstPort))

			var remoteIP net.IP
			var remotePort layers.UDPPort
			var isRx bool
			if udp.SrcPort < udp.DstPort {
				isRx = true
				remoteIP = srcIP
				remotePort = udp.SrcPort
			} else {
				remoteIP = dstIP
				remotePort = udp.DstPort
				isRx = false
			}
			dst := fmt.Sprintf("%s:%d", remoteIP, remotePort)
			if stats[dst] == nil {
				stats[dst] = &stat{}
			}
			stat := stats[dst]
			if isRx {
				stat.packetsRx++
				stat.bytesRx += len(udp.Payload)
			} else {
				stat.packetsTx++
				stat.bytesTx += len(udp.Payload)
			}
		}

		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			fmt.Println("dns")
			dns, _ := dnsLayer.(*layers.DNS)
			for _, q := range dns.Questions {
				if q.Type == layers.DNSTypeA || q.Type == layers.DNSTypeAAAA {
					fmt.Printf("  q: %s %s\n", q.Type, string(q.Name))
				} else {
					fmt.Printf("  q: %s ...\n", q.Type)
				}
			}
			for _, a := range dns.Answers {
				if a.Type == layers.DNSTypeA || a.Type == layers.DNSTypeAAAA || a.Type == layers.DNSTypeCNAME {
					fmt.Printf("  a: %s %s %s\n", a.Type, string(a.Name), a.IP)
				} else {
					fmt.Printf("  a: %s ...\n", a.Type)
				}
			}
		}

		if c%100 == 0 {
			fmt.Println("==========================================================")
			for dst, stat := range stats {
				name := dst
				host, _, _ := net.SplitHostPort(dst)
				if cachedName, ok := addrLookupCache[host]; ok {
					if cachedName == "" {
						name = dst
					} else {
						name = cachedName
					}
				} else {
					names, _ := net.LookupAddr(host)
					if len(names) > 0 {
						name = names[0] + "(" + dst + ")"
						addrLookupCache[host] = name
					} else {
						addrLookupCache[host] = ""
					}
				}
				fmt.Printf("%s -> %#v\n", name, stat)
			}
		}
	}

	fmt.Println("==========================================================")
	for dst, stat := range stats {
		fmt.Printf("%s -> %#v\n", dst, stat)
	}
}
func printPort(mapFile string, port uint16) {
	if port >= localPortMin && port <= localPortMax {
		pid, cmdLine, err := findProcessFor(mapFile, port)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  could not find process: %s\n", err)
		} else {
			fmt.Printf("  process: %d (%s)\n", pid, cmdLine)
		}
	}

}

type process struct {
	pid     int
	cmdLine string
}

var processCache = map[uint16]process{}

func findProcessFor(mapFile string, port uint16) (pid int, cmdLine string, err error) {
	if process, ok := processCache[port]; ok {
		return process.pid, process.cmdLine, nil
	}

	start := time.Now()
	defer func() {
		if pid != -1 {
			fmt.Fprintf(os.Stderr, "  took %s to find process for %d\n", time.Since(start), port)
		}
	}()

	f, err := os.Open(mapFile)
	if err != nil {
		return -1, "", err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	s.Scan()
	if s.Err() != nil {
		return -1, "", s.Err()
	}
	localAddrIdx := strings.Index(s.Text(), "local_address")
	if localAddrIdx < 0 {
		return -1, "", fmt.Errorf("missing 'local_address' field")
	}
	inodeIdx := strings.Index(s.Text(), "inode")
	if inodeIdx < 0 {
		return -1, "", fmt.Errorf("missing 'inode' field")
	}

	portAsHex := fmt.Sprintf(":%X", port)
	for s.Scan() {
		parts := strings.SplitN(s.Text()[localAddrIdx:], " ", 2)
		if len(parts) != 2 {
			return -1, "", fmt.Errorf("could not find local_address field")
		}
		localAddr := parts[0]
		if strings.Contains(localAddr, portAsHex) {
			parts := strings.SplitN(s.Text()[inodeIdx:], " ", 2)
			if len(parts) != 2 {
				return -1, "", fmt.Errorf("could not find inode in %q", s.Text()[inodeIdx:])
			}
			inode := parts[0]
			socketName := fmt.Sprintf("socket:[%s]", inode)

			pf, err := os.Open("/proc")
			if err != nil {
				return -1, "", err
			}
			defer pf.Close()

			fis, err := pf.Readdir(-1)
			for _, fi := range fis {
				if fi.IsDir() && pidRE.MatchString(fi.Name()) {
					fdDir, err := os.Open(path.Join("/proc", fi.Name(), "fd"))
					if err != nil {
						return -1, "", err
					}
					defer fdDir.Close()

					pid, _ := strconv.Atoi(fi.Name())

					fds, err := fdDir.Readdir(-1)
					if err != nil {
						return -1, "", err
					}

					for _, fd := range fds {
						if fd.Mode()&os.ModeSymlink == os.ModeSymlink {
							link, err := os.Readlink(path.Join("/proc", fi.Name(), "fd", fd.Name()))
							if err != nil {
								return -1, "", err
							}
							if link == socketName {
								data, err := ioutil.ReadFile(path.Join("/proc", fi.Name(), "cmdline"))
								if err != nil {
									return -1, "", err
								}
								processCache[port] = process{pid: pid, cmdLine: string(data)}
								return pid, string(data), nil
							}
						}
					}
				}
			}
		}
	}
	if s.Err() != nil {
		return -1, "", s.Err()
	}
	return -1, "", fmt.Errorf("process using port %d not found", port)
}
