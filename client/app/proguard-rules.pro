# Keep JNI methods in MamaCrypto
-keepclassmembers class com.mama40.crypto.MamaCrypto {
    native <methods>;
}
-keep class com.mama40.crypto.** { *; }

# Keep data models if serialized
-keepclassmembers class * {
    @androidx.annotation.Keep <fields>;
    @androidx.annotation.Keep <methods>;
}

# Optimize aggressively
-repackageclasses 'a'
-allowaccessmodification

# Strip verbose/debug logs from release binary
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
}
