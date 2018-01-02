name := "pcapOrgDumper"

version := "0.1.1"

scalaVersion := "2.12.4"

//logLevel := Level.Debug

resolvers ++= Seq(
    "clojars" at "http://clojars.org/repo/",
    "Sonatype-public" at "http://oss.sonatype.org/content/groups/public/"
)

libraryDependencies ++= Seq(
    "org.pcap4j" % "pcap4j-core" % "1.7.2",
    "org.pcap4j" % "pcap4j-packetfactory-static" % "1.7.2",
    "org.rogach" %% "scallop" % "3.1.1",
    "io.circe" %% "circe-yaml" % "0.6.1",
    "commons-net" % "commons-net" % "3.6"
)