package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/guptarohit/asciigraph"
	"github.com/schollz/progressbar"
	"gopkg.in/AlecAivazis/survey.v1"
)

var (
	device       string = "wlan0mon"
	snapshot_len int32  = 1024
	promiscuous  bool   = true
	err          error
	timeout      time.Duration = 1 * time.Second
	handle       *pcap.Handle
	counter      int32 = 0
	buffer       gopacket.SerializeBuffer
  	options      gopacket.SerializeOptions
)

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

func send_beacons() {
    // Open device
    handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil {log.Fatal(err) }
    defer handle.Close()


    dot11CoreLayer := &layers.Dot11{
    Address1: net.HardwareAddr{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
    Address2: net.HardwareAddr{0xFF,0xAA,0xFA,0xAA,0xFF,0xAA},
    Address3: net.HardwareAddr{0xFF,0xAA,0xFA,0xAA,0xFF,0xAA},
    Type: layers.Dot11TypeMgmtBeacon,
    }

    dot11BeaconLayer := &layers.Dot11MgmtBeacon{
			Interval: 100,
		}
    radioLayer := &layers.Ethernet{}

    buffer = gopacket.NewSerializeBuffer()
    gopacket.SerializeLayers(
      buffer,
      options,
      radioLayer,
      dot11CoreLayer,
      dot11BeaconLayer,
      Dot11Info(layers.Dot11InformationElementIDSSID, []byte("TestNetworkSpectrum")),
    )
    outgoingPacket := buffer.Bytes()

     for {
	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
	log.Fatal(err)
	}
     }
}

func main() {

	//	printAChart()

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
		Options: []string{"Start Monitor", "Show beacon statistics", "Look for rogue APs", "Print Beacon Chart"},
	}

	fmt.Print("\n")
	survey.AskOne(prompt, &option_select, nil)

	if option_select == "Start Monitor" {
		fmt.Println("Press key to begin...")
	}

	if option_select == "Show beacon statistics" {
		fmt.Println("Here are the statistics:")
		os.Exit(3)
	}

	if option_select == "Look for rogue APs" {
		fmt.Println("Rogue AP list not detected")
		os.Exit(3)
	}

	if option_select == "Print Beacon Chart" {
		printAChart()
		os.Exit(3)
	}

	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)

	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	//  print_artwork()

	for packet := range packetSource.Packets() {
		display_beacons(packet)
	}

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
			" \u001b[37mDBM AS: \u001b[34m", radioInformation.DBMAntennaSignal,
			" \u001b[37mRate: \u001b[33m", radioInformation.Rate,
			" \u001b[37mTX Attenuation: \u001b[35m", radioInformation.TxAttenuation,
			" \u001b[37mDBTx Attenuation: \u001b[35m", radioInformation.DBTxAttenuation,
			" \u001b[37mDBMTxPower: \u001b[35m", radioInformation.DBMTxPower,
			" \u001b[37mAntenna: \u001b[35m", radioInformation.Antenna, " \u001b[31m Beacons Captured: ", counter)

		if dot11Information.Address3 != nil {
			fmt.Fprintln(f, dot11Information.Address3)
		}

		fmt.Println("")
	}

}

func printAChart() {
	data := []float64{1, 4, 6, 3, 6, 3, 6, 3, 5, 6, 11, 2, 3, 4, 2}
	graph := asciigraph.Plot(data)

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
