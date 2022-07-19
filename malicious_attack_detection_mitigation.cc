 
 // Example of TNNA Attack and its Detection and Mitigation
 // Network Topology-
 /****************************************************************************
  *				Network Topology				*
  *										*	
  *			      (M_S)	     (M_D)				*
  *			      node-3	    node-4	 -			*
  *			    (10.1.1.4)	  (10.1.1.5)	 -			*
  *				-	    -		80m			*
  *				 -	  -		 -			*
  *	   (S)			  - (N)	-		 - (D)		*			 
  *	  node-0 --------------- node-1 ---------------------  node-2	*			 
  *	(10.1.1.1)    70m	(10.1.1.2)	 60m		(10.1.1.3)	*
  *										*
  ***************************************************************************/

#include "ns3/core-module.h"
#include "ns3/config-store-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/aodv-module.h"
#include "ns3/netanim-module.h"
#include "ns3/internet-module.h"
#include "ns3/position-allocator.h"
#include "ns3/applications-module.h"
#include "ns3/network-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/pointer.h"
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <fstream>
#include <vector>
#include <string>

using namespace ns3;


NS_LOG_COMPONENT_DEFINE ("MaliciousAodv");


int main(int argc, char *argv[])

{
//Time::SetResolution (Time::NS);

RngSeedManager::SetRun(1);
RngSeedManager::SetSeed(1);  

uint32_t total_nodes=5;
uint32_t packet_size=512;
std::string Data_Rate="20Kib/s";
std::string phyMode ("DsssRate1Mbps");
bool malicious_detection= false;
bool malicious_mitigation= false;
uint32_t m_packet_size=512;
uint32_t stop_time=150;
bool malicious_attack= true;
std::string m_Data_Rate="100Kib/s";
 CommandLine cmd;
 cmd.AddValue("total_nodes", "Total Nodes", total_nodes);
 cmd.Parse (argc, argv);

  NodeContainer wifiNodeContainer;
  wifiNodeContainer.Create (total_nodes);
  
  NodeContainer not_malicious_nodes;
  NodeContainer malicious_nodes;

  
  
  not_malicious_nodes.Add(wifiNodeContainer.Get(0));
  not_malicious_nodes.Add(wifiNodeContainer.Get(1));
  not_malicious_nodes.Add(wifiNodeContainer.Get(2));
  malicious_nodes.Add(wifiNodeContainer.Get(3));
  malicious_nodes.Add(wifiNodeContainer.Get(4));
 		

Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode",StringValue (phyMode));


WifiHelper wifi;
wifi.SetStandard (WIFI_STANDARD_80211b);

WifiMacHelper wifiMac;
wifiMac.SetType ("ns3::AdhocWifiMac");

wifi.SetRemoteStationManager( "ns3::ConstantRateWifiManager",
                                "DataMode", StringValue (phyMode),
                                "ControlMode", StringValue (phyMode));


  YansWifiPhyHelper wifiPhy;
  YansWifiChannelHelper wifiChannel;
  wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  wifiChannel.AddPropagationLoss ("ns3::LogDistancePropagationLossModel",
					"Exponent", DoubleValue (3.0),
					"ReferenceLoss", DoubleValue (40.0459));

					
  wifiPhy.SetChannel (wifiChannel.Create ());


  //NetDeviceContainer notMalicious_Devices = wifi.Install (wifiPhy, wifiMac, not_malicious_nodes);
  NetDeviceContainer notMalicious_Devices1 = wifi.Install (wifiPhy, wifiMac, wifiNodeContainer.Get(0));
  NetDeviceContainer adhocDevices = notMalicious_Devices1;
  
  if(malicious_detection){
  wifiPhy.Set ("RxSensitivity", DoubleValue (-80.0));
  NetDeviceContainer notMalicious_Devices2 = wifi.Install (wifiPhy, wifiMac, wifiNodeContainer.Get(1));
  adhocDevices.Add(notMalicious_Devices2);
  }
  else{
  NetDeviceContainer notMalicious_Devices2 = wifi.Install (wifiPhy, wifiMac, wifiNodeContainer.Get(1)); 
  adhocDevices.Add(notMalicious_Devices2);
  }
  
  NetDeviceContainer notMalicious_Devices3 = wifi.Install (wifiPhy, wifiMac, wifiNodeContainer.Get(2));
  adhocDevices.Add(notMalicious_Devices3);
  
  NetDeviceContainer malicious_Devices = wifi.Install (wifiPhy, wifiMac, malicious_nodes);
  adhocDevices.Add(malicious_Devices);
  
  MobilityHelper mobility;
  Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator> ();
  positionAlloc->Add (Vector (0.0, 100.0, 0.0));
  positionAlloc->Add (Vector (70.0, 100.0, 0.0));
  positionAlloc->Add (Vector (130.0, 100.0, 0.0));
  positionAlloc->Add (Vector (60.0, 20.0, 0.0));
  positionAlloc->Add (Vector (80, 20.0, 0.0));
  mobility.SetPositionAllocator (positionAlloc);
  mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  mobility.Install (wifiNodeContainer);
  
  
AodvHelper aodv;
AodvHelper maliciousAttack_aodv;
AodvHelper maliciousMitigation_aodv;
InternetStackHelper stack;
stack.SetRoutingHelper (aodv);
stack.Install (wifiNodeContainer.Get(0));
stack.Install (wifiNodeContainer.Get(2));

if(malicious_attack){
maliciousAttack_aodv.Set("IsMalicious", BooleanValue(malicious_attack));
stack.SetRoutingHelper (maliciousAttack_aodv);
stack.Install (malicious_nodes);
}
else{
stack.SetRoutingHelper (aodv);
stack.Install (malicious_nodes);
}


if(malicious_mitigation){
maliciousMitigation_aodv.Set("IsMaliciousMitigation", BooleanValue(malicious_mitigation));
stack.SetRoutingHelper (maliciousMitigation_aodv);
stack.Install (wifiNodeContainer.Get(1));
}
else{
stack.SetRoutingHelper (aodv);
stack.Install (wifiNodeContainer.Get(1));
}

Ipv4AddressHelper address;
address.SetBase ("10.1.1.0", "255.255.255.0");

Ipv4InterfaceContainer interfaces;
interfaces = address.Assign (adhocDevices);

	
 ApplicationContainer cbrApps;
  uint16_t cbrPort = 12345;
  OnOffHelper onOffHelper1 ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address ("10.1.1.3"), cbrPort));
  onOffHelper1.SetAttribute ("PacketSize", UintegerValue (packet_size));
  onOffHelper1.SetAttribute ("OnTime",  StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
  onOffHelper1.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
  onOffHelper1.SetAttribute ("DataRate", StringValue (Data_Rate));
  onOffHelper1.SetAttribute ("StopTime", TimeValue (Seconds (stop_time)));
  cbrApps.Add (onOffHelper1.Install (wifiNodeContainer.Get (0))); 
 
 if(malicious_attack){
  OnOffHelper onOffHelper3 ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address ("10.1.1.5"), cbrPort));
  onOffHelper3.SetAttribute ("PacketSize", UintegerValue (m_packet_size));
  onOffHelper3.SetAttribute ("OnTime",  StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
  onOffHelper3.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
  onOffHelper3.SetAttribute ("DataRate", StringValue (m_Data_Rate));
  onOffHelper3.SetAttribute ("StopTime", TimeValue (Seconds (stop_time)));
  cbrApps.Add (onOffHelper3.Install (wifiNodeContainer.Get (3)));
  
 }
  
// ANIMATION SETTINGS ------------------------------------------------

  AnimationInterface anim ("tnna_attack.xml");
  AnimationInterface::SetConstantPosition (wifiNodeContainer.Get(0), 0, 100);
  AnimationInterface::SetConstantPosition (wifiNodeContainer.Get(1), 70, 100);
  AnimationInterface::SetConstantPosition (wifiNodeContainer.Get(2), 130, 100);
  AnimationInterface::SetConstantPosition (wifiNodeContainer.Get(3), 60, 20); 
  AnimationInterface::SetConstantPosition (wifiNodeContainer.Get(4), 80, 20);
  anim.EnablePacketMetadata(true);

  //set normal node green and increase size
   if(malicious_attack){
  NodeContainer::Iterator i;
  for (i = not_malicious_nodes.Begin (); i != not_malicious_nodes.End (); ++i)
  {
    anim.UpdateNodeColor(*i, 0, 255 , 0);
    anim.UpdateNodeSize((*i)->GetId(), 5.0, 5.0);
  }

//set malicious node colour black and increase size
   for (i = malicious_nodes.Begin (); i != malicious_nodes.End (); ++i)
  {
    anim.UpdateNodeColor(*i, 255, 0 , 0);
    anim.UpdateNodeSize((*i)->GetId(), 6.0, 6.0);
  }
  }

/*Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper> ("sim2.routes", std::ios::out);
  maliciousAttack_aodv.PrintRoutingTableAllEvery (Seconds (1), routingStream);*/
  
  
AsciiTraceHelper ascii;
wifiPhy.EnableAsciiAll (ascii.CreateFileStream ("tnna_attack.tr"));

FlowMonitorHelper flowmonHelper;
Ptr<FlowMonitor> flowmon = flowmonHelper.InstallAll ();




Simulator::Stop (Seconds (stop_time));		
Simulator::Run ();

Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowmonHelper.GetClassifier ());
std::map<FlowId, FlowMonitor::FlowStats> stats = flowmon->GetFlowStats ();

for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator iter = stats.begin (); iter != stats.end (); ++iter)
    {
	  Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (iter->first);

if ((t.sourceAddress == Ipv4Address("10.1.1.1") && t.destinationAddress == Ipv4Address("10.1.1.3"))||(t.sourceAddress == Ipv4Address("10.1.1.4") && t.destinationAddress == Ipv4Address("10.1.1.5"))||(t.sourceAddress == Ipv4Address("10.1.1.5") && t.destinationAddress == Ipv4Address("10.1.1.4")))
       {
          std::cout<<"Flow ID: " << iter->first << " Src Addr " << t.sourceAddress << " Dst Addr " << t.destinationAddress<<"\n";
	   std::cout<<"First Tx Packet Time (Sec) = " << iter->second.timeFirstTxPacket.GetSeconds()<<"\n";
    	   std::cout<<"Total Tx Packets = " << iter->second.txPackets<<"\n";
	   std::cout<<"Total Tx Bytes with Header(28 Bytes on every Packets) = " << iter->second.txBytes<<"\n";
    	   std::cout<<"Total Rx Packets = " << iter->second.rxPackets<<"\n";
	   std::cout<<"Total Rx Bytes with Header(28 Bytes on every Packets) = " << iter->second.rxBytes<<"\n";
           std::cout<<"Last  Rx Packet Time (Sec) = " << iter->second.timeLastRxPacket.GetSeconds()<<"\n";
	   std::cout<<"Mean Delay (sec) = " << iter->second.delaySum.GetSeconds() / iter->second.rxPackets<<"\n";
           std::cout<<"Mean Jitter (sec) = " << iter->second.jitterSum.GetSeconds() / (iter->second.rxPackets - 1)<<"\n";
           std::cout<<"PDR = " << iter->second.rxPackets * 100 / iter->second.txPackets <<" %"<<"\n";
    	   std::cout<<"Throughput (Kibps): " << iter->second.rxBytes * 8.0 / (stop_time) / 1024  << " Kibps" <<"\n";

    	   
     	 }
}

Simulator::Destroy ();	
			
return 0;
}



