#!/bin/bash
BASEDIR=$(dirname $0)/../../..
TARGETDIR=$BASEDIR/target
TESTDIR=$TARGETDIR
CLASSPATH=""
for i in $TESTDIR/lib/*.jar $TARGETDIR/seu-idp*.jar
do
   CLASSPATH=$CLASSPATH:$i
done
export CLASSPATH
$JAVA_HOME/bin/java -Dexe4j.moduleName=$TESTDIR/bin/test es.caib.seycon.config.Config $*
