package com.Insfinity.authcredential.client;

import com.Insfinity.authcredential.ServerBindingConfig;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Locale;

/**
 * 硬件采集与设备指纹。方法名（le/rab/li/ci/kesih）保持与原 jar 一致——
 * 补丁模组注入点：le()（最终指纹）、li()（MAC）、ci()（CPU）、kesih()（系统标识）。
 */
public final class le {
   private static volatile String le = null;

   /** 指纹 = UPPERCASE( HEX( SHA256( raw + deviceSalt ) )[0:32] )。进程内只算一次并缓存。 */
   public static synchronized String le() {
      if (le != null) {
         return le;
      } else {
         String var0 = rab();
         String var1 = var0 + ServerBindingConfig.getDeviceSalt();
         le = li(var1).substring(0, 32).toUpperCase(Locale.ROOT);
         return le;
      }
   }

   private static String rab() {
      StringBuilder var0 = new StringBuilder();
      var0.append("MAC:").append(li()).append(';');
      var0.append("CPU:").append(ci()).append(';');
      var0.append("SYS:").append(kesih()).append(';');
      return var0.toString();
   }

   /** 网卡 MAC 列表（排序、逗号分隔、大写、不去重）。 */
   private static String li() {
      ArrayList<String> var0 = new ArrayList<>();
      try {
         Enumeration<NetworkInterface> var1 = NetworkInterface.getNetworkInterfaces();
         while (var1 != null && var1.hasMoreElements()) {
            NetworkInterface var2 = var1.nextElement();
            if (!var2.isLoopback() && !var2.isVirtual() && !var2.isPointToPoint()) {
               byte[] var3 = var2.getHardwareAddress();
               if (var3 != null && var3.length != 0) {
                  StringBuilder var4 = new StringBuilder();
                  for (byte var8 : var3) {
                     var4.append(String.format("%02X", var8));
                  }
                  var0.add(var4.toString());
               }
            }
         }
      } catch (Exception var9) {
      }
      Collections.sort(var0);
      return String.join(",", var0);
   }

   /** CPU 信息：Windows 取 PROCESSOR_IDENTIFIER / CIM；mac/linux 走 sysctl / cpuinfo。 */
   private static String ci() {
      String var0 = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
      try {
         if (var0.contains("win")) {
            String var1 = System.getenv("PROCESSOR_IDENTIFIER");
            if (var1 != null && !var1.isBlank()) {
               return var1;
            } else {
               String var2 = le("Get-CimInstance Win32_Processor | Select-Object -ExpandProperty ProcessorId");
               return var2 != null && !var2.isBlank() ? var2 : le("Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Name");
            }
         } else {
            return var0.contains("mac")
               ? le("sysctl", "-n", "machdep.cpu.brand_string") + "|" + le("sysctl", "-n", "hw.model")
               : rab("/proc/cpuinfo").replaceAll("(?m)^(?!model name|processor|cpu family).*$", "").replaceAll("\\s+", " ");
         }
      } catch (Exception var3) {
         return "unknown";
      }
   }

   /** 系统标识（主板|BIOS 序列号等）。 */
   private static String kesih() {
      String var0 = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
      try {
         if (var0.contains("win")) {
            String var4 = le("Get-CimInstance Win32_BaseBoard | Select-Object -ExpandProperty SerialNumber");
            String var2 = le("Get-CimInstance Win32_BIOS | Select-Object -ExpandProperty SerialNumber");
            return (var4 != null ? var4 : "") + "|" + (var2 != null ? var2 : "");
         } else if (var0.contains("mac")) {
            return le("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").replaceAll("(?s).*\"IOPlatformUUID\"\\s*=\\s*\"([^\"]+)\".*", "$1");
         } else {
            String var1 = le("cat", "/sys/class/dmi/id/product_uuid");
            return var1 != null && !var1.isBlank() ? var1 : rab("/etc/machine-id");
         }
      } catch (Exception var3) {
         return "unknown";
      }
   }

   /** 通用命令行执行（含参数）。 */
   private static String le(String... var0) {
      try {
         ProcessBuilder var1 = new ProcessBuilder(var0);
         var1.redirectErrorStream(true);
         Process var2 = var1.start();
         StringBuilder var3 = new StringBuilder();
         try (BufferedReader var4 = new BufferedReader(new InputStreamReader(var2.getInputStream(), StandardCharsets.UTF_8))) {
            String var5;
            while ((var5 = var4.readLine()) != null) {
               var3.append(var5).append('\n');
            }
         }
         var2.waitFor();
         return var3.toString().trim().replaceAll("\\s+", " ");
      } catch (Exception var9) {
         return "";
      }
   }

   /** PowerShell 命令执行。 */
   private static String le(String var0) {
      try {
         ProcessBuilder var1 = new ProcessBuilder("powershell", "-NoProfile", "-NonInteractive", "-Command", var0);
         var1.redirectErrorStream(true);
         Process var2 = var1.start();
         StringBuilder var3 = new StringBuilder();
         try (BufferedReader var4 = new BufferedReader(new InputStreamReader(var2.getInputStream(), StandardCharsets.UTF_8))) {
            String var5;
            while ((var5 = var4.readLine()) != null) {
               var3.append(var5).append('\n');
            }
         }
         var2.waitFor();
         return var3.toString().trim().replaceAll("\\s+", " ");
      } catch (Exception var9) {
         return "";
      }
   }

   /** 读取文件。 */
   private static String rab(String var0) {
      try {
         return new String(Files.readAllBytes(Paths.get(var0)), StandardCharsets.UTF_8).trim().replaceAll("\\s+", " ");
      } catch (Exception var2) {
         return "";
      }
   }

   /** SHA-256 十六进制；异常时退化为 hashCode。 */
   private static String li(String var0) {
      try {
         MessageDigest var1 = MessageDigest.getInstance("SHA-256");
         byte[] var2 = var1.digest(var0.getBytes(StandardCharsets.UTF_8));
         StringBuilder var3 = new StringBuilder();
         for (byte var7 : var2) {
            var3.append(String.format("%02x", var7));
         }
         return var3.toString();
      } catch (Exception var8) {
         return String.format("%064d", Math.abs((long)var0.hashCode()));
      }
   }
}