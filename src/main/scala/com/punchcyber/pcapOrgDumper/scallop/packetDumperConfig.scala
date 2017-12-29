package com.punchcyber.pcapOrgDumper.scallop

import java.io.File

import com.punchcyber.pcapOrgDumper.util.interfaceList.getInterfaceListString
import org.rogach.scallop.{ScallopConf, ScallopOption}

class packetDumperConfig(arguments: Seq[String]) extends ScallopConf(arguments) {
    val config_file: ScallopOption[String] = opt[String](
        required = true,
        name = "config-file",
        descr = "YAML configuration file containing application settings.  Default file is ./packetDumper_config.yaml")
    
    version(
        """
          |(c) 2017-2018 Punch Cyber Analytics Group https://punchcyber.com/
          |""".stripMargin)
    
    banner(
        """
          |Usage: packetDumper [-c /full/path/to/your/config/file.yaml]
          |=========-=========-=========-=========-=========-=========-=========-=========
          |  This application listens for packets on a network interface filtering on a
          |  one or more TCP or UDP ports.  All application settings are defined in a
          |  YAML formatted configuration file.
        """.stripMargin)
    
    // Let's list available network interfaces as a convenience
    private val interfaceString: String = getInterfaceListString
    
    footer(
        s"""
          |=========-=========-=========-=========-=========-=========-=========-=========
          |Just in case there is no example config file, here are all the settings:
          |
          |  # This is the network interface we want to listen on
          |  interface: "en0"
          |
          |  # Maximum number of threads.  If this value is set to 0, then all available
          |  # resources will be used
          |  maxThreads: 0
          |
          |  # Sampling rate.  record 1 packet out of every N packets.  If this value is
          |  # not set, then no sampling will be performed.  Setting a sample rate of 1
          |  # will have the same effect as not setting this value.
          |  sampleRate: 1
          |
          |  # Specify the port(s) we wish to collect
          |  ports:
          |    - 25
          |    - 80
          |    - 443
          |    - 22
          |    - 137
          |
          |  # Specify the root directory for PCAP file output.  If the directory does
          |  # not exist, we will create it, so ensure that the user running the app
          |  # has sufficient privileges (e.g. minimum of read/write)
          |  root: "/Users/mbossert/test_output"
          |
          |  # Approximate output file size with postfix units (e.g. B, KB, MB, GB, TB)
          |  fileSize: 1 GB
          |
          |  # List of Organization IP address(es) and/or ranges.  If this argument is
          |  # not supplied, no filter will be applied and all sessions will be
          |  # assumed to be associated with one organization.
          |  orgs:
          |    - name: "ORG1"
          |      cidr: ["10.0.11.0/24","10.0.33.0/24","10.0.66.0/24"]
          |    - name: "TEST_ORG"
          |      cidr: ["192.168.86.0/24"]
          |    - name: "ORG3"
          |      cidr: ["10.0.234.0/24"]
          |
          |=========-=========-=========-=========-=========-=========-=========-=========
          |Available Network Interfaces:
          |$interfaceString
        """.stripMargin)
    
    validate(config_file) { (config_file) =>
        val fileToCheck: File = new File(config_file)
        if(fileToCheck.exists() && fileToCheck.isFile && fileToCheck.canRead) Right(Unit)
        else if(!fileToCheck.exists) Left("It is much easier to read configuration files that EXIST.")
        else if(!fileToCheck.isFile) Left("Looks like \"" + fileToCheck.getAbsolutePath + "\" is NOT A FILE.")
        else if(!fileToCheck.canRead) Left("When using configuration files, it is customary to ensure that the configuration file is READABLE.")
        else Left("Well, we have no clue why that file is no good.  It might be time to contact the developer.")
    }
    
    verify()
}
