


package main


import (

    "fmt"
    "os"
    "os/exec"
    //"bufio"
    "log"
    "time"
    "net"
    "github.com/fatih/color"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "github.com/schollz/progressbar"
    //"sync/atomic"
)


var (

    device       string = "wlan0mon"
    snapshot_len int32  = 1024
    promiscuous  bool   = true
    err          error
    timeout      time.Duration = 1 * time.Second
    handle       *pcap.Handle
)

func init() {

}


func main(){

    rotate()
    addrs, err := net.InterfaceAddrs()
    if err != nil {
            os.Stderr.WriteString("There was an error: " + err.Error() + "\n")
            os.Exit(1)
        }
    fmt.Println("__________________________________________________________________________")
    for _, a := range addrs {
            if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
                    if ipnet.IP.To16() != nil {

                            os.Stdout.WriteString("\nAddress assigned to network interface: " + ipnet.IP.String() + "\n")
                    }
            }
    }
    fmt.Println("__________________________________________________________________________")


  color.Yellow("\n\nPlease select an option:")

  handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)

  if err != nil {
    log.Fatal(err)
  }

  defer handle.Close()
  packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

//  print_artwork()

  toucanMainMenu := `
------------------
1. START MONITOR
------------------
  `
  fmt.Println(toucanMainMenu)
  color.Magenta("Press any key to begin... ")



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
    if dot11Information != nil || radioInformation != nil{
      c := exec.Command("clear")
      c.Stdout = os.Stdout
      c.Run()

      dot11Information, _ := dot11Information.(*layers.Dot11)
      //dot11elementInformation, _ := dot11elementInformation.(*layers.Dot11InformationElement)
      radioInformation, _ := radioInformation.(*layers.RadioTap)

      fmt.Print("\n")
      fmt.Println("Capturing beacons on intf: ", device)
      fmt.Println("____________________________________________")
      color.Red("Station: %v\n", dot11Information.Address3)
      fmt.Fprintln(f, dot11Information.Address3)
      fmt.Println("____________________________________________")
      //fmt.Println(dot11elementInformation.Info)
      color.Yellow("Destination: %v\n", dot11Information.Address1)
      fmt.Println("____________________________________________")
      color.Red("Data: %v\n", dot11Information.Type)
      color.Yellow("SequenceNumber")
      fmt.Println(dot11Information.SequenceNumber)
      color.Red("Frequency:")
      fmt.Println(radioInformation.ChannelFrequency)
      color.Yellow("DBM AS:")
      fmt.Println(radioInformation.DBMAntennaSignal)
      color.Red("DBM Noise:")
      fmt.Println(radioInformation.DBMAntennaNoise)
      color.Yellow("Rate:")
      fmt.Println(radioInformation.Rate)
      fmt.Println("____________________________________________")
      color.Magenta("TX Attenuation:")
      fmt.Println(radioInformation.TxAttenuation)
      color.Magenta("DBTx Attenuation:")
      fmt.Println(radioInformation.DBTxAttenuation)
      color.Magenta("DBMTxPower:")
      fmt.Println(radioInformation.DBMTxPower)
      color.Magenta("Antenna:")
      fmt.Println(radioInformation.Antenna)
      fmt.Println("____________________________________________")
      fmt.Println("\n")
      //fmt.Printf("Power: %v\n", radioInformation.Version)
    }

}


func print_artwork(){
  color.Blue(`

                                              KATANA
 ...../yhhhhhhhhhhddmmNNmddmmmmmmmmmmmmmmmmmmmmmmmmmmMMMmmmmh//yNNmNmdmmmmmNNmmmmmmdddmddddddh
....+yhdhysysyhddmmNmddddddmmmmmmmmmmmmmmmmmmmmmmmmNMNmmmmh/:::/hmNmmmdmmmmmNNmdddmdddmmddyymd
..:shddhhhhhyyshmmmdddddmmmdddmmdmmddddmddmmmddmmmNNmddmmh:::::::yNmmmmddddmmNNNmddddhhmmddddmm
:shdmmdddddddmmmdddhydmmmddddmmdmdddddmddmmddmmmNNmmddmmy::::::::oNmddddddddddmNNNmdddddmNmmddmd
ddmmmddddmmmmmmddddmmmdssyhdmmmmddddmmdmmddmmdmmmmddmmmo:::::::::ommddddddhysyhdmNNNmmmddmNNNmmmy
NNmmmmmmNmmmmmmmmNNmmdhhyhmNNmdhyydmmmmdhdmmmmmdmddmdh/::::::::::hymhyyhdddhddddddddmmmmmmmNNNNmm:
NmmmmNNy/dmmmmNNNNmmmdmmNNNdddddmNmmmmddmmmdyddmmmhy+:::::::::::+yoyhhhhdddddddmmddmmmmdddmmmNNNmds
NNNNh+-.sNNNMMNNmmmmmNNNmdddmmNNNmmmmdmmmds/ydmdys+::::::::::::+o+:/dddddddddddmNNNNNNNNNNNmmmmNNd+y
my+-...+NMMMNNNNNNNMNNmdmmNNNNNNmmdddmmho/:smds/::::::::::::::::/:::hdddddddddmmmmmNNNMddNNNNNNmmm+.
......+NNNNNNNNNNNNmmmNNMMMNNNmmmshmmyo/::+mh/::::::::::::::::::::::sdddddmmmmmmmNsymmNm-+mmmNNNNmdh
..:+omNNNNNNNNNNNmNNNNNMMMMNNmmm+/mh+/::::hd/:::::::::::::::/+o+/:::+hddddmmmmmNmNN:/dmNh.-dmmNNNs.o
:+sydNNNNNNMNNNNNNMMNNNMMMNmmNm+/sd++::::/m+::::::::::::/oyyyo+oooossdddmmmmmmmNNmNh..ymN/-mmmNm-
--:hNNNNNNNNNMMNNNMMMNNMNNmNNNsoshssyyyyyhmo/:::::::::/shhhdNNMMNNNmo+dmmmmmNmmmNNNN:  smh
.smNNNNNNNNNMNNNNNNMMMNNNNMMNmdMNNNNNNNNmms/oo/:::::::+/sdyshssyo+o/-:ymmmmmNNNmNNNNm   sm
mNNNNNNNNNNNNNNNNNNNNNNNMMNh/::so++so/s/:s/::://::::::::::--:----:::::+dNmmmmNNNmNNNmd  h:
NNNNNNNNNNNNNNNNNNNNNNNMMdo:::::/:---/:-::::::::::::::::::::::::::::::/sNmmmmNNNNmNNN:
NNNNNNNNNNNNNNNNNNNNNNNNNm/::::::::::::::::::::::::::::::::::::::::::::+mNmmmNNNNmmNN:
NNNNmmmmmmmmmNNNNNNNNNNNNNms/:--::::::::::::::::::::::::::::::::::----:yNNNmmmNNNmmmmoom-
mmmmmmd+-:hmmmNNNNNNNNNNmNmo++::---:::::::::::::::::::::::::::::------+mNNNNmmmNmmmmmhh+dh
dhhmd+.--ommmNNNNmmmNNmNNNNm/-----------:--:::::::::::::::::---------/dNNNmNmmmNmmddddyysds
+yy/----/mmmmNNmmmNmNNNNNNNmmo----------------:::::::::::-----------:dNNNmmmNmmmmmdmsshdddd
+.-----dmhmmNmmmmNmmNNNNNNNNNs:----------------:+/::/:------------:hNNmmmNNmmmmmddd-.:+yhso
        m+sdmmmymmmmNNNNNmmNNNNd/-----------------::--------------:hNmmmdmNNmdohmd       o+
         :ddds.mmmNNNNdo-hNNNNNmy/------------------::://-------/dmmho/hmmmh:   dd
           +dh. hmmmmo---.mNNNNdmNdo:-------:::::::::-:-------:syo:..ommmy/
            /y--dmmo----ommNNyh+mNNms/:-------://++++:-----:+o:-+shys/.-y
             .  dm+  :mmmd+s/omNNNmsso+/----------------   /
                    .+mdy//+.-mmmdo-.sssso+/----------- /
                                        ooooo+/-----:/

`)
}


func print_artwork2(){
  color.Green(`

                  ./.                                                        ./.
                -oo-                                                          -oo.
              -/m/                                                             -/m/-
            .ym:                                                                :my.
          -dm:            -.                                         .-          :md-
        :mN:           -s:                                            :s-          :Nm:
      -mM+          -sd:                                              :ds-          +Mm-
      .dMh          -dm:                                                :md-          hMd.
      yMN-         -mM/           --                        .-           /Mm:         -NMy
      :MMs         -mMs          -/s.                        .s/-          sMm-         sMM:
      hMN-        -hMm.         -hm-                          -Nh-         .mMh         -NMh
      -NMd-        /MMo         -mM+           .-::-.-          +Mm-         sMM/        -dMN-
      +MMs         dMN-        -mMd-        -:ymNNNNmy:-        -dMm-        -MMd         sMM+
      yMM+        .NMm-        +MMo         oNMMMMMMMMNo         oMM+        -mMN.        +MMy
      dMM/        -NMd-        yMM/        .MMMMMMMMMMMM.        /MMy        -dMN-        /MMh
      hMM/        -NMd-        yMM/        .NMMMMMMMMMMN.        /MMy        -dMN-        /MMh
      sMM+        .NMm.        /MMs         +NMMMMMMMMm+         sMM/        -mMN.        +MMs
      +MMy         hMM:        -dMm-         -sMMMMMMs.         -mMd-        :MMh         yMM+
      .NMm-        :MMs         -dMo          sMMMMMMs-         oMm.         sMM:        -mMN.
      yMM:         yMN.         .yN:        /NMMMMMMN/        :Ny.         .NMh         :MMh
      -MMy         .dMy           :s-      .mMMMMMMMMm.      -s:           yMd.         yMM-
        sMN:         .dM+            -      hMMMMMMMMMMh      -            +Md.         -NMs
        -dMd-         .hN/                 +MMMMMNNMMMMM+                 /Nh.         -dMd-
        .mMo           +m/               -NMMMMM++MMMMMN-               /m+-          sMd.
          .mN/           .o+             -mMMMMMy  hMMMMMd.             +o.           +Nm.
          .dN/            -.           -yMMMMMm-  -mMMMMMs            .-            /Nh.
            -oN/                        /MMMMMM:    :NMMMMM/                        /No-
              :do-                     .NMMMMMo      oMMMMMN.                      oh-
              -+s.                   -hMMMMMd:-    -:dMMMMMd-                   .o+-
                -:.                  oMMMMMN--/+--+/--NMMMMMo                  .:-
                  -                 :NMMMMM/  .oddo.  /MMMMMN:                 -
                                   .mMMMMMy-/yh+-./hy/-yMMMMMm.
                                   yMMMMMNymd/.    -+dmyNMMMMMy
                                  +MMMMMMMd/-        -/dMMMMMMM+
                                 -NMMMMNh/-            -/hMMMMMN-
                                -dMMMMMh-                -hMMMMMd-
                               -sMMMMMN/.-              -./mMMMMMs-
                               /NMMMMN/.:o/--        --/o:-/NMMMMN/
                              .NMMMMMs   -:syo--  --oys:-   sMMMMMm.
                             -hMMMMMd-     --oddssddo--     -dMMMMMh-
                             oMMMMMN-      -.:yMNNMy:.-      -NMMMMMo
                            :NMMMMM+    -.:ymNNy::yNMmy:.-    +MMMMMN:
                           .dMMMMMh  -./ymMMms-    -smNMmy/.-  yMMMMMd.
                           yMMMMMm-.+hNMMNd+.        .+dNMMNh+.-mMMMMMy-
                          /MMMMMMhhNMMMNh:-            -:hNMMMNhhMMMMMM/
                         -NMMMMMMMMMMms--                 -smMMMMMMMMMMN-
                        -hMMMMMMMMMd+.                      -+dMMMMMMMMMh-
                        oMMMMMMMNh:-                          -/hNMMMMMMMo
                       -mMMMMMNs-                                -sNMMMMMd-
                        :hNNd+-                                    .+dNNh:





`)
}


func print_artwork3(){
  color.Red(`

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
                                time.Sleep(200 * time.Millisecond)
                                printB()
                                time.Sleep(200 * time.Millisecond)
                                printC()
                                time.Sleep(200 * time.Millisecond)
                                printA()
                                time.Sleep(200 * time.Millisecond)
                                printB()
                                time.Sleep(300 * time.Millisecond)
                                printC()
                                time.Sleep(2000 * time.Millisecond)
                                fmt.Println("\n")
                                clearscreen2 := exec.Command("clear")
                                clearscreen2.Stdout = os.Stdout
                                clearscreen2.Run()
                                color.Red("\nKATANA LOADING...\n")
                                fmt.Println("\n")
                                bar := progressbar.New(100)
                                for i := 0; i < 100; i++ {
                                    bar.Add(1)
                                    time.Sleep(10 * time.Millisecond)
                                }
                                clearscreen := exec.Command("clear")
                                clearscreen.Stdout = os.Stdout
                                clearscreen.Run()
                                break;
                }
}
