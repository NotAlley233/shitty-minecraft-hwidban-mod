package com.Insfinity.authcredential.client;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Enumeration;
import java.util.Locale;

/**
 * 虚拟机启发式检测。方法名 dofuw 为补丁模组注入点（dofuw()Z -> 强制 isVM）。
 * 四组启发式（JVM/CPU 关键词、网卡 OUI 前缀、DMI 厂商/型号、Windows BIOS 注册表）。
 */
public final class rab {
   private static final String[] rab = new String[]{
      "vmware", "virtualbox", "qemu", "kvm", "hyper-v", "hyperv", "xen", "parallels", "bhyve", "vbox", "bochs", "kvmvm"
   };
   private static final String[] li = new String[]{
      "vmware", "virtualbox", "vbox", "qemu", "kvm", "hyper-v", "xen", "parallels", "bhyve", "bochs", "virtual machine", "vmw", "innotek"
   };
   private static final String[] ci = new String[]{
      "000569", "000C29", "001C14", "005056", "080027", "525400", "00163E", "001C42", "001DD8", "0003FF", "00155D", "000F4B"
   };

   public static boolean dofuw() {
      return met() || nax() || bugul() || sap();
   }

   private static boolean met() {
      String var0 = System.getProperty("java.vm.info", "")
         + " "
         + System.getProperty("sun.management.compiler", "")
         + " "
         + System.getenv().getOrDefault("PROCESSOR_IDENTIFIER", "");
      String var1 = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
      if (var1.contains("mac")) {
         var0 = var0 + " " + rab("sysctl", "-n", "machdep.cpu.brand_string");
      } else if (var1.contains("nux")) {
         var0 = var0 + " " + ci("/proc/cpuinfo");
      } else if (var1.contains("win")) {
         var0 = var0 + " " + le("Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Name");
      }
      var0 = var0.toLowerCase(Locale.ROOT);
      for (String var5 : rab) {
         if (var0.contains(var5)) {
            return true;
         }
      }
      return false;
   }

   private static boolean nax() {
      try {
         Enumeration<NetworkInterface> var0 = NetworkInterface.getNetworkInterfaces();
         while (var0 != null && var0.hasMoreElements()) {
            NetworkInterface var1 = var0.nextElement();
            if (!var1.isLoopback()) {
               byte[] var2 = var1.getHardwareAddress();
               if (var2 != null && var2.length >= 3) {
                  String var3 = String.format("%02X%02X%02X", var2[0], var2[1], var2[2]);
                  for (String var7 : ci) {
                     if (var7.equals(var3)) {
                        return true;
                     }
                  }
               }
            }
         }
      } catch (Exception var8) {
      }
      return false;
   }

   private static boolean bugul() {
      String var0 = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
      String var1 = "";
      if (var0.contains("win")) {
         var1 = le("Get-CimInstance Win32_ComputerSystem | Select-Object -ExpandProperty Model")
            + " "
            + le("Get-CimInstance Win32_BIOS | Select-Object -ExpandProperty SerialNumber")
            + " "
            + le("Get-CimInstance Win32_BaseBoard | Select-Object -ExpandProperty Manufacturer");
      } else if (var0.contains("mac")) {
         var1 = rab("ioreg", "-rd1", "-c", "IOPlatformExpertDevice");
      } else if (var0.contains("nux")) {
         var1 = ci("/sys/class/dmi/id/product_name")
            + " "
            + ci("/sys/class/dmi/id/sys_vendor")
            + " "
            + ci("/sys/class/dmi/id/board_vendor")
            + " "
            + ci("/sys/class/dmi/id/bios_vendor");
      }
      var1 = var1.toLowerCase(Locale.ROOT);
      for (String var5 : li) {
         if (var1.contains(var5)) {
            return true;
         }
      }
      return false;
   }

   private static boolean sap() {
      String var0 = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
      if (var0.contains("nux")) {
         String var1 = ci("/proc/cpuinfo");
         if (var1.toLowerCase(Locale.ROOT).contains("hypervisor")) {
            return true;
         }
         String var2 = ci("/sys/class/dmi/id/product_name");
         if (!var2.isBlank()
            && (
               var2.toLowerCase(Locale.ROOT).contains("virtual")
                  || var2.toLowerCase(Locale.ROOT).contains("kvm")
                  || var2.toLowerCase(Locale.ROOT).contains("qemu")
            )) {
            return true;
         }
         String var3 = ci("/proc/scsi/scsi");
         if (var3.toLowerCase(Locale.ROOT).contains("vmware")) {
            return true;
         }
      }
      if (var0.contains("mac")) {
         String var4 = rab("ioreg", "-l");
         String var6 = var4.toLowerCase(Locale.ROOT);
         if (var6.contains("vmware") || var6.contains("parallels") || var6.contains("virtualbox") || var6.contains("qemu")) {
            return true;
         }
         if (var4.contains("AppleVirtualPlatform") || var4.contains("Parallels")) {
            return true;
         }
      }
      if (var0.contains("win")) {
         String var5 = rab("reg", "query", "HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS", "/v", "SystemManufacturer");
         String var7 = var5.toLowerCase(Locale.ROOT);
         if (var7.contains("vmware") || var7.contains("virtual") || var7.contains("qemu") || var7.contains("xen") || var7.contains("parallels")) {
            return true;
         }
      }
      return false;
   }

   private static String rab(String... var0) {
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
         return var3.toString();
      } catch (Exception var9) {
         return "";
      }
   }

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
         return var3.toString();
      } catch (Exception var9) {
         return "";
      }
   }

   private static String ci(String var0) {
      try {
         return new String(Files.readAllBytes(Paths.get(var0)), StandardCharsets.UTF_8);
      } catch (Exception var2) {
         return "";
      }
   }
}