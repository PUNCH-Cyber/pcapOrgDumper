package com.punchcyber.pcapOrgDumper.utils

import io.circe.Json
import org.apache.commons.net.util.SubnetUtils

import scala.collection.mutable.ArrayBuffer
import scala.util.matching.Regex

class pcapDumperSettings(settings: Json) {
    private def filesizeToBytes(filesizeString: String): Long = {
        val sizeKB: Long = 1024L
        val sizeMB: Long = 1024L * sizeKB
        val sizeGB: Long = 1024L * sizeMB
        val sizeTB: Long = 1024L * sizeGB
        
        val pattern: Regex = """(\d+)\s*(B|KB|MB|GB|TB)""".r
        val pattern(size,unit) = filesizeString
        
        if(unit == "KB") size.toLong * sizeKB
        else if(unit == "MB") size.toLong * sizeMB
        else if(unit == "GB") size.toLong * sizeGB
        else if(unit == "TB") size.toLong * sizeTB
        else size.toLong
    }
    
    // INTERFACE
    val interface: String = settings.\\("interface").head.as[String].right.get
    
    // MaxThreads
    val maxThreads: Int = settings.\\("maxThreads").head.as[Int].right.get
    
    // Ports
    val ports: Array[Int] = {
        val portIter: Iterator[Json] = settings.\\("ports").head.as[List[Json]].right.get.toIterator
        val portArray: ArrayBuffer[Int] = ArrayBuffer[Int]()
        while(portIter.hasNext) {
            portArray += portIter.next().as[Int].right.get
        }
        portArray.toArray
    }
    
    // Root directory
    val rootDir: String = settings.\\("root").head.as[String].right.get
    
    // File size
    val fileSize: Long = filesizeToBytes(settings.\\("fileSize").head.as[String].right.get)
    
    // ORGS
    val orgArray: Array[String] = {
        val orgArrayBuffer: ArrayBuffer[String] = ArrayBuffer[String]()
        val settingsIter: Iterator[Json] = settings.\\("orgs").iterator
    
        while(settingsIter.hasNext) {
            val orgNameList: List[Json] = settingsIter.next().\\("name")
            
            for(org <- orgNameList) {
                orgArrayBuffer += org.as[String].right.get
            }
        }
        orgArrayBuffer.toArray
    }
    
    val cidrArray: Array[(SubnetUtils,String)] = {
        val cidrArrayBuffer: ArrayBuffer[(SubnetUtils,String)] = ArrayBuffer()
        val settingsIter: Iterator[Json] = settings.\\("orgs").iterator
        
        while(settingsIter.hasNext) {
            val orgEntry: Json = settingsIter.next()
            val orgNameList: List[Json] = orgEntry.\\("name")
            val cidrArrayList: List[Json] = orgEntry.\\("cidr")
        
            var count: Int = 0
            while(count < orgNameList.length) {
                val orgString: String = orgNameList(count).as[String].right.get
                val cidrList: Array[String] = cidrArrayList(count).as[Array[String]].right.get
                for(cidr <- cidrList) {
                    cidrArrayBuffer += ((new SubnetUtils(cidr), orgString))
                }
                count += 1
            }
        }
        cidrArrayBuffer.toArray
    }
    
    // Log output directory
    val logDir: String = settings.\\("logRootDirectory").head.as[String].right.get
    
    // Log rotation time
    val logRotateTime: String = settings.\\("logRotationTime").head.as[String].right.get
    
    // Max log age.  Delete after this age in days
    val logMaxAge: Int = settings.\\("logMaxAge").head.as[Int].right.get
    
    // Metric resolution/bucket size measured in sec., min., or hours (e.g. S, M, H)
    val metricResolution: String = settings.\\("measurementResolution").head.as[String].right.get
}
