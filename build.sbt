ThisBuild / scalaVersion := "3.2.2"
ThisBuild / organization := "io.moov"

lazy val hello = (project in file("."))
  .settings(
    name := "sigtesting"
  )

// This .jar is loaded from lib/
// libraryDependencies += "com.mastercard.ap.security" % "xmlsignverify-core-java" % "1.0.0"

libraryDependencies ++= Seq(
  "org.apache.santuario" % "xmlsec" % "2.2.3",
  "net.sf.saxon" % "Saxon-HE" % "10.1"
)
