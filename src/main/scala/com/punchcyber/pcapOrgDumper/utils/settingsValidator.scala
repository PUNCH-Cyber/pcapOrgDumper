package com.punchcyber.pcapOrgDumper.utils

import java.io.File

import com.punchcyber.pcapOrgDumper.utils.interfaceList.getInterfaceList
import io.circe.Json
import io.circe.yaml.parser

import scala.util.matching.Regex

object settingsValidator {
    private def validateOrg(orgString: String): Boolean = {
        // Really, we could be less restrictive is allowable characters, but this is safer.
        // TODO: Let's revisit this with the client to ensure we are not making life needlessly difficult
        if(orgString.matches("[a-zA-Z0-9_]+")) true
        else false
    }
    
    private def validateCidrBlock(cidrString: String): Boolean = {
        // TODO: Clearly we need to support IPV6
        val pattern: Regex = """(\d+).(\d+).(\d+).(\d+)\/(\d+)""".r
        val pattern(i1,i2,i3,i4,m) = cidrString
        if((i1.toInt  >= 0 && i1.toInt <= 255) &&
            (i2.toInt >= 0 && i2.toInt <= 255) &&
            (i3.toInt >= 0 && i3.toInt <= 255) &&
            (i4.toInt >= 0 && i4.toInt <= 255) &&
            (m.toInt  >= 0 && m.toInt  <= 32)) {
            true
        }
        else false
    }
    
    private def validateSampleRate(sampleRate: Int): Boolean = {
        if(sampleRate > 0) true
        else false
    }
    
    private def validateRootDirectory(directoryString: String): Boolean = {
        val rootDirectory: File = new File(directoryString)
        
        if(rootDirectory.isDirectory && rootDirectory.canRead && rootDirectory.canWrite) true
        else if(rootDirectory.mkdirs()) true
        else false
    }
    
    private def validateInterface(interfaceString: String): Boolean = {
        // TODO: Need to think about further validation other than just checking that the interface exists
        val interfaceList: List[String] = getInterfaceList.toList
        
        if(interfaceList.contains(interfaceString)) true
        else false
    }
    
    private def validatePort(portInteger: Int): Boolean = {
        if(portInteger >= 1 && portInteger <= 65535) true
        else false
    }
    
    private def validateFilesize(filesizeString: String): Boolean = {
        // All we are doing is checking for a number followed by one of B,KB,MB,GB, or TB
        if(filesizeString.matches("""\d+\s*(B|KB|MB|GB|TB)""")) true
        else false
    }
    
    private def validateLogDir(logDirectoryString: String): Boolean = {
        val logDirectory: File = new File(logDirectoryString)
    
        if(logDirectory.isDirectory && logDirectory.canRead && logDirectory.canWrite) true
        else if(logDirectory.mkdirs()) true
        else false
    }
    
    private def validateLogRotateTime(timeString: String): Boolean = {
        val pattern: Regex = """T(\d+):(\d+):(\d+)""".r
        val pattern(i1,i2,i3) = timeString
        if((i1.toInt  >= 0 && i1.toInt <= 23) &&
            (i2.toInt >= 0 && i2.toInt <= 59) &&
            (i3.toInt >= 0 && i3.toInt <= 59)) {
            true
        }
        else false
    }
    
    private def validateLogMaxAge(days: Int): Boolean = {
        if(days > 0) true
        else false
    }
    
    private def validateCompressAge(days: Int): Boolean = {
        if(days > 0) true
        else false
    }
    
    private def validateMetricResolution(resolutionString: String): Boolean = {
        // All we are doing is checking for one of S, M, H
        if(resolutionString.matches("""(S|M|H)""")) true
        else false
    }
    
    def validateAll(configFileString: String): Boolean = {
        parser.parse(scala.io.Source.fromFile(configFileString).mkString) match {
            case Left(error) => throw error
            case Right(json) =>
                // INTERFACE
                val interface: String = json.\\("interface").head.as[String].right.get
                if(!validateInterface(interface)) { System.err.println("Network interface not found: " + interface); return false }
            
                // MaxThreads
                val maxThreads: Int = json.\\("maxThreads").head.as[Int].right.get
            
                // Ports
                val portIter: Iterator[Json] = json.\\("ports").head.as[List[Json]].right.get.toIterator
                while(portIter.hasNext) {
                    val port: Int = portIter.next().as[Int].right.get
                    if(!validatePort(port)) { System.err.println("Ports must be an integer between 1 and 65535."); return false }
                }
            
                // Root directory
                val rootDir: String = json.\\("root").head.as[String].right.get
                if(!validateRootDirectory(rootDir)) { System.err.println("Root directory does not exist or cannot be read."); return false }
            
                // File size
                val fileSize: String = json.\\("fileSize").head.as[String].right.get
                if(!validateFilesize(fileSize)) { System.err.println("File size must be expressed as a number followed by a unit of measure (B, KB, MB, GB, or TB)"); return false }
            
                // ORGS
                val jsonIter: Iterator[Json] = json.\\("orgs").iterator
                while(jsonIter.hasNext) {
                    val orgEntry: Json = jsonIter.next()
                    val orgNameList: List[Json] = orgEntry.\\("name")
                    val cidrArrayList: List[Json] = orgEntry.\\("cidr")
                
                    var count: Int = 0
                    while(count < orgNameList.length) {
                        val orgString: String = orgNameList(count).as[String].right.get
                        if(!validateOrg(orgString)) { System.err.println("Organization name may only consist of alpha-numeric characters and underscore \"_\" "); return false }
                    
                        val cidrList: Array[String] = cidrArrayList(count).as[Array[String]].right.get
                        for(cidr <- cidrList) {
                            if(!validateCidrBlock(cidr)) { System.err.println("Cidr block " + cidr + " Does not appear to be valid"); return false }
                        }
                        count += 1
                    }
                }
    
                // Log output directory
                val logDir: String = json.\\("logRootDirectory").head.as[String].right.get
                if(!validateLogDir(logDir)) { System.err.println("Log directory does not exist or cannot be read."); return false }
    
                // Log rotation time
                val logRotateTime: String = json.\\("logRotationTime").head.as[String].right.get
                if(!validateLogRotateTime(logRotateTime)) { System.err.println("Log rotation time should be expressed as a number of hours, minutes, and seconds, for example: 23:59:59"); return false }
    
                // Max log age.  Delete after this age in days
                val logMaxAge: Int = json.\\("logMaxAge").head.as[Int].right.get
                if(!validateLogMaxAge(logMaxAge)) { System.err.println("Max log age must be larger than 0 days."); return false }
    
                // Metric resolution/bucket size measured in sec., min., or hours (e.g. S, M, H)
                val metricResolution: String = json.\\("measurementResolution").head.as[String].right.get
                if(!validateMetricResolution(metricResolution)) { System.err.println("Metric resolution must be a number greater than 0 with a unit of measure (S, M, H)"); return false }
        }
        true
    }
}
