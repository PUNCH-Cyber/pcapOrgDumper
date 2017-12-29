package com.punchcyber.pcapOrgDumper.util

import java.net.NetworkInterface
import java.util

import scala.collection.mutable.ArrayBuffer

object interfaceList extends Serializable {
    def getInterfaceListString: String = {
        val interfaces: util.Enumeration[NetworkInterface] = NetworkInterface.getNetworkInterfaces
        val interfaceList: util.concurrent.ConcurrentSkipListSet[NetworkInterface] = new util.concurrent.ConcurrentSkipListSet[NetworkInterface]((o1: NetworkInterface,o2: NetworkInterface) => {
            o1.getIndex.compareTo(o2.getIndex)
        })
    
        // Unfortunately, the Java Enumeration does not spit out the interfaces in numeric order, so extra work for us.
        while(interfaces.hasMoreElements) {
            interfaceList.add(interfaces.nextElement())
        }
    
        val interfaceIter: util.Iterator[NetworkInterface] = interfaceList.iterator()
        var interfaceString: String = ""
    
        while(interfaceIter.hasNext) {
            val interface: NetworkInterface = interfaceIter.next()
            interfaceString += "  " + f"${interface.getIndex}%2d" + " " + interface.getDisplayName + "\n"
        }
        interfaceString
    }
    
    def getInterfaceList: ArrayBuffer[String] = {
        val interfaces: util.Enumeration[NetworkInterface] = NetworkInterface.getNetworkInterfaces
        var interfaceList: ArrayBuffer[String] = ArrayBuffer[String]()
        while(interfaces.hasMoreElements) {
            interfaceList += interfaces.nextElement().getDisplayName
        }
        interfaceList
    }
}
