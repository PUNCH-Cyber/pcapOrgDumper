package com.punchcyber.pcapOrgDumper

import java.sql.Timestamp
import java.text.SimpleDateFormat
import java.time.Instant
import java.util.Date
import java.util.concurrent.{ExecutorService, Executors, TimeUnit}

import com.punchcyber.pcapOrgDumper.scallop.packetDumperConfig
import com.punchcyber.pcapOrgDumper.util.pcapDumperSettings
import com.punchcyber.pcapOrgDumper.util.settingsValidator.validateAll
import io.circe.yaml.parser
import org.pcap4j.core.PcapHandle.TimestampPrecision
import org.pcap4j.core._
import org.pcap4j.packet.IpV4Packet.IpV4Header
import org.pcap4j.packet.TcpPacket.TcpHeader
import org.pcap4j.packet.{IpV4Packet, Packet, TcpPacket}
import org.pcap4j.packet.namednumber.DataLinkType

import scala.collection.mutable
import scala.language.postfixOps
import scala.util.control.Breaks._

object pcapOrgDumper {
    def main(args: Array[String]): Unit = {
        val conf = new packetDumperConfig(args)
        
        val configFile: String = conf.config_file()
    
        if(!validateAll(configFile)) throw new IllegalArgumentException
        else {
            parser.parse(scala.io.Source.fromFile(configFile).mkString) match {
                case Left(error) => throw error.getCause
                case Right(json) =>
                    val settings: pcapDumperSettings = new pcapDumperSettings(json)
                    
                    // Open our network interface and get some details
                    val nif: PcapNetworkInterface = Pcaps.getDevByName(settings.interface)
                    val nifHandle: PcapHandle = nif.openLive(65536,PcapNetworkInterface.PromiscuousMode PROMISCUOUS,10000)
                    val dlt: DataLinkType = nifHandle.getDlt
                    val tsPrecision: TimestampPrecision = nifHandle.getTimestampPrecision
    
                    // Create output files to write to
                    val outputDumpers: mutable.HashMap[String,PcapDumper] = mutable.HashMap[String,PcapDumper]()
                    
                    for(org <- settings.orgArray) {
                        val pcapHandle: PcapHandle = Pcaps.openDead(dlt,65536,tsPrecision)
                        val dumper: PcapDumper = pcapHandle.dumpOpen(settings.rootDir + "/" + org + "_" + new SimpleDateFormat("yyyyMMddHHmmss").format(new Date()) + ".pcap")
                        outputDumpers.put(org,dumper)
                        pcapHandle.close()
                    }
                    
                    // Start listening for packets
                    if(nifHandle.isOpen) {
                        val listener: PacketListener = (packet: Packet) => {
                            if(packet.contains(classOf[TcpPacket])) {
                                val timestamp: Timestamp = nifHandle.getTimestamp
                                val ipHeader: IpV4Header = packet.get(classOf[IpV4Packet]).getHeader
                                val tcpHeader: TcpHeader = packet.get(classOf[TcpPacket]).getHeader
                                val sip: String = ipHeader.getSrcAddr.getHostAddress
                                val dip: String = ipHeader.getDstAddr.getHostAddress
                                val sport: Int = tcpHeader.getSrcPort.valueAsInt()
                                val dport: Int = tcpHeader.getDstPort.valueAsInt()
                                
                                val stats: PcapStat = nifHandle.getStats
                                val dropped: Long = stats.getNumPacketsDropped
                                
                                // TODO: For now, just log to STDERR when packets are dropped.  Proper logging might be a good next step
                                if(dropped > 0) System.err.println(Instant.now + " : " + dropped)
                                
                                breakable {
                                    for((cidr,org) <- settings.cidrArray) {
                                        if((cidr.getInfo.isInRange(sip) || cidr.getInfo.isInRange(dip))
                                            && (settings.ports.contains(sport) || settings.ports.contains(dport))) {
                                            synchronized {
                                                outputDumpers(org).dump(packet,timestamp)
                                            
                                                if(outputDumpers(org).ftell() > settings.fileSize) {
                                                    outputDumpers(org).flush()
                                                    outputDumpers(org).close()
                                                    
                                                    val pcapHandle: PcapHandle = Pcaps.openDead(dlt,65536,tsPrecision)
                                                    val dumper: PcapDumper = pcapHandle.dumpOpen(settings.rootDir + "/" + org + "_" + new SimpleDateFormat("yyyyMMddHHmmss").format(new Date()) + ".pcap")
                                                    
                                                    outputDumpers.put(org,dumper)
                                                    pcapHandle.close()
                                                }
                                            }
                                            break()
                                        }
                                    }
                                }
                                
                            }
                        }
                        
                        try {
                            val pool: ExecutorService = Executors.newFixedThreadPool(settings.maxThreads)
                            nifHandle.loop(1000000,listener,pool)
                            pool.awaitTermination(30,TimeUnit.SECONDS)
                            if(!pool.isShutdown) pool.shutdown()
                        } catch {
                            case e: InterruptedException =>
                                System.err.println(e.getCause + "\n" + e.getStackTrace.mkString("\n"))
                        } finally {
                            nifHandle.close()
                        }
                    }
                    else {
                        nifHandle.close()
                        throw new PcapNativeException()
                    }
                    
            }
        }
    }
}