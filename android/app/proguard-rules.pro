# Keep WireGuard backend (loaded via reflection/JNI) and data classes.
-keep class com.wireguard.** { *; }
-keep class com.privatewire.vpn.** { *; }
-dontwarn com.wireguard.**
