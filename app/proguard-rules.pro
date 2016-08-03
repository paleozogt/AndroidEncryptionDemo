# logback has special needs
-keep class ch.qos.** { *; }
-keep class org.slf4j.** { *; }
-dontwarn ch.qos.logback.core.net.*
