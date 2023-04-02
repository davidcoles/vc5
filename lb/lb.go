package lb

import (
	//"fmt"
	"errors"
	"log"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/davidcoles/vc5/config2"
	"github.com/davidcoles/vc5/healthchecks"
	"github.com/davidcoles/vc5/kernel"
	"github.com/davidcoles/vc5/monitor"
	"github.com/davidcoles/vc5/netns"
	"github.com/davidcoles/vc5/types"
)

const NAMESPACE = "vc5"
const VC5A = "vc5a"
const VC5B = "vc5b"

var vc5aip [4]byte = [4]byte{10, 255, 255, 253}
var vc5bip IP4 = IP4{10, 255, 255, 254}

type IP4 = types.IP4
type L4 = types.L4
type NET = types.NET
type Target = kernel.Target
type Status = monitor.Report

func LoadConf(file string) (*config2.Conf, error) {
	return config2.Load(file)
}

func NetnsServer(sock string) {
	netns.Server(sock, vc5bip.String())
}

type LoadBalancer struct {
	ReadinessLevel  uint8
	KillSwitch      uint
	Native          bool
	MultiNIC        bool
	Socket          string
	NetnsCommand    []string
	Interfaces      []string
	EgressInterface string
	Logger          types.Logger

	monitor  *monitor.Mon
	balancer *kernel.Balancer
	nat      *kernel.NAT
	maps     *kernel.Maps
	report   monitor.Report
	update   chan *healthchecks.Healthchecks
	mutex    sync.Mutex
}

func (lb *LoadBalancer) Stats() (kernel.Counter, map[kernel.Target]kernel.Counter) {
	return lb.balancer.Global(), lb.balancer.Stats()
}

func (lb *LoadBalancer) Status() monitor.Report {
	lb.mutex.Lock()
	r := lb.report
	lb.mutex.Unlock()
	return r
}

func (lb *LoadBalancer) DEFCON(d uint8) uint8 {
	return lb.maps.DEFCON(d)
}

func (lb *LoadBalancer) Close() {
	close(lb.update)
	clean(VC5A, NAMESPACE)
}

func (lb *LoadBalancer) Update(hc *healthchecks.Healthchecks) {
	lb.update <- hc
}

func (lb *LoadBalancer) Start(ipaddr net.IP, hc *healthchecks.Healthchecks) error {

	ip4 := ipaddr.To4()

	if ip4 == nil {
		return errors.New("Not an IPv4 address")
	}

	ip := IP4{ip4[0], ip4[1], ip4[2], ip4[3]}

	l := lb.Logger

	if l == nil {
		l = &types.NilLogger{}
	}

	var cleanup bool = true

	defer func() {
		if cleanup {
			clean(VC5A, NAMESPACE)
		}
	}()

	bond := lb.EgressInterface
	peth := lb.Interfaces
	native := lb.Native
	args := lb.NetnsCommand
	sock := lb.Socket

	var vc5amac [6]byte
	var vc5bmac [6]byte

	var bondidx int
	var bondmac [6]byte

	if bond != "" {
		iface, err := net.InterfaceByName(bond)
		if err != nil {
			return err
		}
		bondidx = iface.Index
		copy(bondmac[:], iface.HardwareAddr[:])
	} else {
		iface, err := net.InterfaceByName(peth[0])
		if err != nil {
			return err
		}
		bondidx = iface.Index
		copy(bondmac[:], iface.HardwareAddr[:])
	}

	setup1(VC5A, VC5B)

	iface, err := net.InterfaceByName(VC5A)
	if err != nil {
		return err
	}
	copy(vc5amac[:], iface.HardwareAddr[:])

	vc5aidx := iface.Index

	iface, err = net.InterfaceByName(VC5B)
	if err != nil {
		return err
	}
	copy(vc5bmac[:], iface.HardwareAddr[:])

	lb.maps, err = kernel.Open(native, VC5A, VC5B, peth...)

	if err != nil {
		return err
	}

	lb.maps.MODE(lb.MultiNIC)

	if lb.ReadinessLevel != 0 {
		lb.DEFCON(lb.ReadinessLevel)
	}

	cleanup = false

	setup2(NAMESPACE, VC5A, VC5B, vc5aip, vc5bip)

	go netns.Spawn(NAMESPACE, args...)

	lb.nat = &kernel.NAT{
		Maps: lb.maps,

		DefaultIP:     ip,
		PhysicalMAC:   bondmac,
		PhysicalIndex: bondidx,

		VC5aIf: vc5aidx,
		VC5aIP: vc5aip,
		VC5bIP: vc5bip,

		VC5aMAC: vc5amac,
		VC5bMAC: vc5bmac,

		Logger: l,
	}

	//var hc2 *healthchecks.Healthchecks
	//lb.nat, hc2 = lb.maps.NAT(hc, ip, bondidx, bondmac, vc5aidx, vc5aip, vc5bip, vc5amac, vc5bmac, l)

	hc2 := lb.nat.NAT(hc)

	lb.monitor, lb.report = monitor.Monitor(hc2, sock, l)
	lb.balancer = lb.maps.Balancer(lb.report, l)

	lb.update = make(chan *healthchecks.Healthchecks)

	go lb.background()

	if lb.KillSwitch > 0 {
		// temporary auto kill switch
		go func() {
			for {
				time.Sleep(time.Duration(lb.KillSwitch) * time.Minute)
				lb.DEFCON(0)
			}
		}()
	}

	return nil
}

func (lb *LoadBalancer) background() {

	go func() {
		defer lb.balancer.Close()
		for h := range lb.monitor.C {
			log.Println("MONITOR update")
			lb.mutex.Lock()
			lb.report = *(h.DeepCopy())
			lb.mutex.Unlock()
			lb.balancer.Configure(h)
		}
	}()

	go func() {
		defer lb.monitor.Close()
		for h := range lb.nat.C {
			log.Println("NAT update")
			lb.monitor.Update(h)
		}
	}()

	defer lb.nat.Close()
	for h := range lb.update {
		log.Println("CONF update")
		lb.nat.Configure(h)
	}
}

/**********************************************************************/

func clean(if1, ns string) {
	script1 := `
    ip link del ` + if1 + ` >/dev/null 2>&1 || true
    ip netns del ` + ns + ` >/dev/null 2>&1 || true
`
	exec.Command("/bin/sh", "-e", "-c", script1).Output()
}

func setup1(if1, if2 string) {
	script1 := `
ip link del ` + if1 + ` >/dev/null 2>&1 || true
ip link add ` + if1 + ` type veth peer name ` + if2 + `
`
	_, err := exec.Command("/bin/sh", "-e", "-c", script1).Output()
	if err != nil {
		log.Fatal(err)
	}
}

func setup2(ns, if1, if2 string, i1, i2 IP4) {
	ip1 := i1.String()
	ip2 := i2.String()
	cb := i1
	cb[2] = 0
	cb[3] = 0
	cbs := cb.String()

	script1 := `
ip netns del ` + ns + ` >/dev/null 2>&1 || true
ip l set ` + if1 + ` up
ip a add ` + ip1 + `/30 dev ` + if1 + `
ip netns add ` + ns + `
ip link set ` + if2 + ` netns ` + ns + `
ip netns exec vc5 /bin/sh -c "ip l set ` + if2 + ` up && ip a add ` + ip2 + `/30 dev ` + if2 + ` && ip r replace default via ` + ip1 + ` && ip netns exec ` + ns + ` ethtool -K ` + if2 + ` tx off"
ip r replace ` + cbs + `/16 via ` + ip2 + `
`
	_, err := exec.Command("/bin/sh", "-e", "-c", script1).Output()
	if err != nil {
		log.Fatal(err)
	}
}

/**********************************************************************/
/*
func (lb *LoadBalancer) LoadConf(file string, mynet NET) (*healthchecks.Healthchecks, error) {
	conf, err := config2.Load(file)

	if err != nil {
		return nil, err
	}

	//j, _ := json.MarshalIndent(conf, "", "  ")
	//if false {
	//	fmt.Println(string(j))
	//	return
	//}

	return healthchecks.Load(mynet, conf)
}
*/

func (lb *LoadBalancer) Load(conf *config2.Conf) (*healthchecks.Healthchecks, error) {
	return healthchecks.Load(conf)
}
