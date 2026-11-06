// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
    "bytes"
    "encoding/binary"
    "net"
    "testing"
    "time"
)

func TestDiagnosticSenderIndicesAreBoundedAndDoNotChangeWireGuardPackets(t *testing.T) {
    server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127,0,0,1)})
    if err != nil { t.Fatal(err) }; defer server.Close()
    socket, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
    if err != nil { t.Fatal(err) }
    connection := newNativeConn([]net.Conn{socket}, []uint16{443})
    defer connection.Close()
    for index:=uint32(1); index<=20; index++ {
        packet:=make([]byte,148);packet[0]=1
        binary.LittleEndian.PutUint32(packet[4:8],index)
        copy(packet[8:],[]byte("SYNTHETIC_HANDSHAKE_BODY_MUST_NOT_BE_LOGGED"))
        if n,err:=connection.Write(packet);err!=nil || n!=len(packet){t.Fatalf("write: %v",err)}
        server.SetReadDeadline(time.Now().Add(time.Second))
        received:=make([]byte,512);n,_,err:=server.ReadFromUDP(received)
        if err!=nil || !bytes.Equal(received[:n],packet){t.Fatal("instrumentation changed packet",err)}
    }
    connection.eventMu.Lock();count:=connection.events["INIT_INDEX"];connection.eventMu.Unlock()
    if count!=16 {t.Fatalf("unbounded sender index event count: %d",count)}
}
