package com.punchcyber.pcapOrgDumper

import java.util
import java.io._
import java.text.SimpleDateFormat
import java.time._
import java.time.temporal.ChronoUnit
import java.util.{Calendar, Date, GregorianCalendar}
import java.util.concurrent.{ExecutorService, Executors, TimeUnit}
import java.util.zip.GZIPOutputStream

import com.punchcyber.pcapOrgDumper.scallop.packetDumperConfig
import com.punchcyber.pcapOrgDumper.utils.{TimedAtomicLong, pcapDumperSettings}
import com.punchcyber.pcapOrgDumper.utils.settingsValidator.validateAll
import io.circe.yaml.parser
import org.apache.commons.io.FileUtils
import org.pcap4j.core.PcapHandle.TimestampPrecision
import org.pcap4j.core._
import org.pcap4j.packet.IpV4Packet.IpV4Header
import org.pcap4j.packet.TcpPacket.TcpHeader
import org.pcap4j.packet.{IpV4Packet, TcpPacket}
import org.pcap4j.packet.namednumber.DataLinkType

import scala.collection.mutable
import scala.language.postfixOps
import scala.util.control.Breaks._
import scala.util.matching.Regex
import scala.concurrent._
import ExecutionContext.Implicits.global

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
                        val testFile: File = new File(settings.rootDir + "/" + org)
                        if((testFile.isDirectory && testFile.canRead && testFile.canWrite) || testFile.mkdirs()) {
                            val dumper: PcapDumper = pcapHandle.dumpOpen(settings.rootDir + "/" + org + "/" + org + "_" + new SimpleDateFormat("yyyyMMddHHmmss").format(new Date()) + ".pcap")
                            outputDumpers.put(org,dumper)
                            pcapHandle.close()
                        }
                        else {
                            throw new SecurityException("Cannot read/create directory: " + settings.rootDir + "/" + org + "/")
                        }
                    }
    
                    // We will track metrics here
                    var fileName: String = settings.logDir + "/" + "pcapOrgDumper_" + new SimpleDateFormat("yyyyMMddHHmmss").format(new Date()) + ".metrics"
                    var logfile: File = new File(fileName)
                    var writer: BufferedWriter = new BufferedWriter(new FileWriter(logfile))
                    writer.write(f"""${"TIME STAMP"}%21s | ${"TOTAL"}%12s | ${"DROPPED"}%12s | ${"DROPPED BY IF"}%12s""" + "\n")
                    writer.flush()
                    
                    val metrics_total: util.concurrent.ConcurrentSkipListMap[Instant,TimedAtomicLong] = new util.concurrent.ConcurrentSkipListMap[Instant,TimedAtomicLong]()
                    val metrics_dropped: util.concurrent.ConcurrentSkipListMap[Instant,TimedAtomicLong] = new util.concurrent.ConcurrentSkipListMap[Instant,TimedAtomicLong]()
                    val metrics_droppedByIf: util.concurrent.ConcurrentSkipListMap[Instant,TimedAtomicLong] = new util.concurrent.ConcurrentSkipListMap[Instant,TimedAtomicLong]()
                    
                    val truncate_to: ChronoUnit = {
                        settings.metricResolution match {
                            case "S" => ChronoUnit.SECONDS
                            case "M" => ChronoUnit.MINUTES
                            case "H" => ChronoUnit.HOURS
                        }
                    }
    
                    val pattern: Regex = """T(\d+):(\d+):(\d+)""".r
                    val pattern(lrH,lrM,lrS) = settings.logRotateTime
                    val lrHl: Int = lrH.toInt
                    val lrMl: Int = lrM.toInt
                    val lrSl: Int = lrS.toInt
                    
                    // TODO: Need to think about making the timezone configurable, but for now, UTC seems to make sense
                    val calendar: Calendar = GregorianCalendar.from(ZonedDateTime.ofInstant(Instant.now(),ZoneId.of("UTC")))
                    calendar.set(Calendar.HOUR_OF_DAY,lrHl.toInt)
                    calendar.set(Calendar.MINUTE,lrMl.toInt)
                    calendar.set(Calendar.SECOND,lrSl.toInt)
                    var rolltime: Instant = calendar.toInstant
                    
                    // Start listening for packets
                    if(nifHandle.isOpen) {
                        val listener: PacketListener = (packet: PcapPacket) => {
                            if(packet.contains(classOf[TcpPacket])) {
                                val timestamp: Instant = packet.getTimestamp
                                val ipHeader: IpV4Header = packet.get(classOf[IpV4Packet]).getHeader
                                val tcpHeader: TcpHeader = packet.get(classOf[TcpPacket]).getHeader
                                val sip: String = ipHeader.getSrcAddr.getHostAddress
                                val dip: String = ipHeader.getDstAddr.getHostAddress
                                val sport: Int = tcpHeader.getSrcPort.valueAsInt()
                                val dport: Int = tcpHeader.getDstPort.valueAsInt()
                                
                                // Collect capture stats
                                val stats: PcapStat = nifHandle.getStats
                                val dropped: Long = stats.getNumPacketsDropped
                                val droppedByIf: Long = stats.getNumPacketsDroppedByIf
                                val total: Long = stats.getNumPacketsReceived
                                val truncated: Instant = timestamp.truncatedTo(truncate_to)
                                
                                metrics_total.computeIfAbsent(truncated, (_: Instant) => {
                                    new TimedAtomicLong(0L)
                                }).addSetAndGet(total)
    
                                metrics_dropped.computeIfAbsent(truncated, (_: Instant) => {
                                    new TimedAtomicLong(0L)
                                }).addSetAndGet(dropped)
    
                                metrics_droppedByIf.computeIfAbsent(truncated, (_: Instant) => {
                                    new TimedAtomicLong(0L)
                                }).addSetAndGet(droppedByIf)
    
                                synchronized {
                                    if(metrics_total.firstEntry().getValue.lastWrittenTo.until(Instant.now(),ChronoUnit.SECONDS) > 10) {
                                        writer.write(f"""${truncated.toString}%21s | ${metrics_total.firstEntry().getValue.get()}%12d | ${metrics_dropped.firstEntry().getValue.get()}%12d | ${metrics_droppedByIf.firstEntry().getValue.get()}%12d""" + "\n")
                                        writer.flush()
                                        
                                        try {
                                            metrics_total.remove(metrics_total.firstKey())
                                            metrics_dropped.remove(metrics_dropped.firstKey())
                                            metrics_droppedByIf.remove(metrics_droppedByIf.firstKey())
                                        }
                                    }
                                    
                                    
                                    if(timestamp.isAfter(rolltime)) {
                                        writer.flush()
                                        writer.close()
    
                                        // Now that we have rolled the log file, set our cutoff for tomorrow at the same time
                                        calendar.add(Calendar.DAY_OF_YEAR,1)
                                        rolltime = calendar.toInstant
    
                                        // Finally, Gzip the old file and delete files older than our retention period
                                        Future {
                                            val fis = new FileInputStream(fileName)
                                            val fos = new FileOutputStream(fileName + ".gz")
                                            val gos = new GZIPOutputStream(fos)
    
                                            var oneByte = fis.read()
                                            
                                            while (oneByte != -1) {
                                                gos.write(oneByte)
                                                oneByte = fis.read()
                                            }
                                            gos.close()
                                            FileUtils.deleteQuietly(new File(fileName))
                                            
                                            val logDirectory: File = new File(settings.logDir)
                                            val fileList: Iterator[File] = logDirectory.listFiles.filter(_.isFile).toIterator
                                            while(fileList.hasNext) {
                                                val thisFile: File = fileList.next()
                                                if(Instant.ofEpochMilli(thisFile.lastModified()).until(Instant.now(),ChronoUnit.DAYS) > settings.logMaxAge) FileUtils.deleteQuietly(thisFile)
                                            }
                                        }
                                        
                                        fileName = settings.logDir + "/" + "pcapOrgDumper_" + new SimpleDateFormat("yyyyMMddHHmmss").format(new Date()) + ".metrics"
                                        logfile = new File(fileName)
                                        writer = new BufferedWriter(new FileWriter(logfile))
                                        writer.write(f"""${"TIME STAMP"}%21s | ${"TOTAL"}%12s | ${"DROPPED"}%12s | ${"DROPPED BY IF"}%12s""" + "\n")
                                        writer.flush()
                                    }
                                    
                                }
                                
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
                                                    val dumper: PcapDumper = pcapHandle.dumpOpen(settings.rootDir + "/" + org + "/" + org + "_" + new SimpleDateFormat("yyyyMMddHHmmss").format(new Date()) + ".pcap")
                                                    
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
                            val pool: ExecutorService = {
                                // If we have maxThreads set to 0, then all available, otherwise, fixedThreadPool
                                if(settings.maxThreads == 0) Executors.newCachedThreadPool()
                                else Executors.newFixedThreadPool(settings.maxThreads)
                            }
                            nifHandle.loop(-1,listener,pool)
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