# [User Guide](https://henryssondaniel.github.io/teacup.github.io/)
[![Build Status](https://travis-ci.com/HenryssonDaniel/teacup-visualization-web-back-java.svg?branch=master)](https://travis-ci.com/HenryssonDaniel/teacup-visualization-web-back-java)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=HenryssonDaniel_teacup-visualization-web-back-java&metric=coverage)](https://sonarcloud.io/dashboard?id=HenryssonDaniel_teacup-visualization-web-back-java)
[![latest release](https://img.shields.io/badge/release%20notes-1.0.0-yellow.svg)](https://github.com/HenryssonDaniel/teacup-visualization-web-back-java/blob/master/doc/release-notes/official.md)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.henryssondaniel.teacup.visualization/web.svg)](http://search.maven.org/#search%7Cgav%7C1%7Cg%3A%22io.github.henryssondaniel.teacup.visualization%22%20AND%20a%3A%22web%22)
[![Javadocs](https://www.javadoc.io/badge/io.github.henryssondaniel.teacup.visualization/web.svg)](https://www.javadoc.io/doc/io.github.henryssondaniel.teacup.visualization/web)
## What ##
Visualization web back-end written in Java.
## Why ##
This project is needed so that the web front-end can interact with the server side and other Teacup
projects.
## How ##
Follow the steps below:
1. Deploy the war file on your server  

For developers: 
1. Add plugin: id 'org.gretty' version 'x.x.x' 
1. Add dependency compile 'org.jboss.resteasy:resteasy-jaxrs:x.x.x'
1. Add dependency compile 'org.jboss.resteasy:resteasy-servlet-initializer:x.x.x'
1. Run: gradle run