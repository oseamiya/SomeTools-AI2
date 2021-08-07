package tech.oseamiya.sometools;

import android.app.Activity;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.provider.Settings;
import android.util.Log;
import com.google.appinventor.components.annotations.SimpleFunction;
import com.google.appinventor.components.annotations.SimpleEvent;
import com.google.appinventor.components.runtime.AndroidNonvisibleComponent;
import com.google.appinventor.components.runtime.ComponentContainer;
import android.content.Context;
import com.google.appinventor.components.runtime.EventDispatcher;
import com.google.appinventor.components.runtime.util.AsynchUtil;
import com.google.appinventor.components.runtime.util.YailList;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.SocketException;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.net.NetworkInterface;
import java.util.ArrayList;

import tech.oseamiya.sometools.NetworkInformation;

public class Sometools extends AndroidNonvisibleComponent {
    private Activity activity;
  private Context context;
  public Sometools(ComponentContainer container) {
    super(container.$form());
    this.context = container.$context();
    this.activity = (Activity) container.$context();
  }

  @SimpleFunction
    public boolean IsDeviceRooted(){
     if(checkRootMethod1() || checkRootMethod2()){
         return true;
     }else{
         return checkRootMethod3();
     }
  }

  @SimpleFunction
  public boolean IsADBDebuggingEnabled(){
      return Settings.Secure.getInt(this.context.getContentResolver(), "adb_enabled" , 0) > 0 ;
  }

  @SimpleFunction
  public boolean IsEmulator(){
      /* Codes were arranged from flutter open-source and google crashlytics */
      String androidId = Settings.Secure.getString(this.context.getContentResolver(), "android_id");
      return "sdk".equals(Build.PRODUCT) || "google_sdk".equals(Build.PRODUCT) || androidId == null ||
              (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")) ||
              Build.FINGERPRINT.startsWith("generic") ||
              Build.FINGERPRINT.startsWith("unknown") ||
              Build.HARDWARE.contains("goldfish") ||
              Build.HARDWARE.contains("ranchu") ||
              Build.MODEL.contains("google_sdk") ||
              Build.MODEL.contains("Emulator") ||
              Build.MANUFACTURER.contains("Genymotion") ||
              Build.PRODUCT.contains("sdk_google") ||
              Build.PRODUCT.contains("google_sdk") ||
              Build.PRODUCT.contains("sdk") ||
              Build.PRODUCT.contains("emulator") ||
              Build.PRODUCT.contains("simulator") ||
              Build.PRODUCT.contains("sdk_x86") ||
              Build.PRODUCT.contains("vbox86p") ||
              Build.MODEL.contains("Android SDK built for x86");
  }

  @SimpleFunction
  public String GetInstallerPackageName(){
      return this.context.getPackageManager().getInstallerPackageName(this.context.getPackageName());
  }
  @SimpleFunction
  public boolean IsAppInstalledFromPlayStore(){
      return GetInstallerPackageName() != null && (GetInstallerPackageName().contains("com.android.vending") || GetInstallerPackageName().contains("com.google.android.feedback"));
  }
  @SimpleFunction
  public boolean IsAppInstalledFromAmazonAppStore(){
      return GetInstallerPackageName() != null && (GetInstallerPackageName().contains("com.amazon.venezia"));
  }
  @SimpleFunction
  public String GetApplicationPackageName(){
      return this.context.getPackageName();
  }
  @SimpleFunction(description = "Get the list of dangerous application in the device")
  public YailList ListOfDangerousAppInDevice(){
      List<ApplicationInfo> applicationList = this.context.getPackageManager().getInstalledApplications(0);
      ArrayList arrayList = new ArrayList();
      for(ApplicationInfo applicationInfo : applicationList){
          String applicationPackageName = applicationInfo.packageName;
          String applicationName = getApplicationName(applicationPackageName).toLowerCase();
          if(applicationPackageName.contains("cc.madkite.freedom") || applicationName.contains("apk analyzer") || applicationName.contains("app analyzer") || applicationName.contains("apk editor") || applicationName.contains("app editor") || applicationPackageName.contains("devadvance.rootcloak") || applicationPackageName.contains(".robv.android.xposed.installer") || applicationPackageName.contains(".saurik.substrate") || applicationPackageName.contains(".devadvance.rootcloakplus") || applicationPackageName.contains(".zachspong.temprootremovejb") || applicationPackageName.contains(".amphoras.hidemyroot") || applicationPackageName.contains(".formyhm.hideroot") || applicationPackageName.contains(".koushikdutta.rommanager") || applicationPackageName.contains(".dimonvideo.luckypatcher") || applicationPackageName.contains(".chelpus.lackypatch") || applicationPackageName.contains(".ramdroid.appquarantine") || applicationPackageName.contains("sk.styk.martin.apkanalyzer")){
              arrayList.add(applicationPackageName);
          }
      }
      return YailList.makeList(arrayList);
  }
  @SimpleFunction
  public YailList GetListOfAllSuperUserApk(){
      List<ApplicationInfo> applicationList = this.context.getPackageManager().getInstalledApplications(0);
      ArrayList arrayList = new ArrayList();
      for(ApplicationInfo applicationInfo : applicationList){
          String applicationPackageName = applicationInfo.packageName;
          if(applicationPackageName.contains(".noshufou") || applicationPackageName.contains(".superuser") || applicationPackageName.contains(".superuser.apk") || applicationPackageName.contains(".yellowes.su") || applicationPackageName.contains(".chainfire.supersu") || applicationPackageName.contains(".thirdparty.superuser") || applicationPackageName.contains(".koushikdutta.superuser")){
              arrayList.add(applicationPackageName);
          }
      }
      return YailList.makeList(arrayList);
  }
  @SimpleFunction
  public void FetchExternalIp1(){
      GetExternalIP("http://ipinfo.io/ip");
  }
  @SimpleFunction
  public void FetchExternalIp2(){
      GetExternalIP("http://ip.42.pl/raw");
  }
  @SimpleFunction
  public void FetchExternalIp3(){
      GetExternalIP("http://ip.3322.org/ip");
  }
  @SimpleFunction
  public void FetchExternalIp4(){
      GetExternalIP("https://wtfismyip.com/text");
  }
  private void GetExternalIP(String weburl) {
    final String website = weburl;
    AsynchUtil.runAsynchronously(new Runnable() {
        @Override
        public void run() {
            BufferedReader in;
            try {
                in = new BufferedReader(
                        new InputStreamReader(
                                new URL(website).openStream()));

                String inputLine;
                final StringBuilder result = new StringBuilder();

                while ((inputLine = in.readLine()) != null)
                    result.append(inputLine);

                in.close();

                activity.runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        GotExternalIP(result.toString());
                    }
                });
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    });
}

@SimpleEvent
public void GotExternalIP(String ip) {
    EventDispatcher.dispatchEvent(this, "GotExternalIP", ip);
}
  @SimpleFunction
  public String GetRadioVersion(){
      return Build.getRadioVersion();
  }
  @SimpleFunction
  public boolean isVpnConnection(){
      return Settings.Secure.getInt(this.context.getContentResolver(), "vpn_state", 0) == 1 || isvpn1() || isvpn2();
  }
  @SimpleFunction
  public String GetIpAddress(boolean useIPv4){
    NetworkInformation networkInformation = new NetworkInformation(this.context);
    return networkInformation.getIpAddress(useIPv4);
}
  
  private boolean isvpn1() {
    String iface = "";
    try {
        for (NetworkInterface networkInterface : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            if (networkInterface.isUp())
                iface = networkInterface.getName();
                Log.d("DEBUG", "IFACE NAME: " + iface);
            if ( iface.contains("tun") || iface.contains("ppp") || iface.contains("pptp")) {
                return true;
            }
        }
    } catch (SocketException e1) {
        e1.printStackTrace();
    }

    return false;
}
private boolean isvpn2() {
    ConnectivityManager cm = (ConnectivityManager) this.context.getSystemService(Context.CONNECTIVITY_SERVICE);
    Network activeNetwork = cm.getActiveNetwork();
    NetworkCapabilities caps = cm.getNetworkCapabilities(activeNetwork);
    boolean vpnInUse = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
    return vpnInUse;
}
  private static boolean checkRootMethod1(){
      String buildTags = Build.TAGS;
      return buildTags != null && buildTags.contains("test-keys");
  }
  private static boolean checkRootMethod2(){
      String[] paths = {"/system/app/Superuser.apk" , "/sbin/su" , "/system/bin/su" , "/system/xbin/su" ,"/system/bin/failsafe/su" , "/data/local/su" , "/su/bin/su" };
      for(String path : paths){
          if(new File(path).exists()){
              return true;
          }
      }
      return false;
  }
  private String getApplicationName(String packageName){
    PackageManager packageManager = this.context.getPackageManager();
    try {
        return (String) packageManager.getApplicationLabel(packageManager.getApplicationInfo(packageName , PackageManager.GET_META_DATA));
    } catch (PackageManager.NameNotFoundException e) {
        e.printStackTrace();
        return "Unknown";
    }
}
  private static boolean checkRootMethod3(){
      Process process = null;
      try {
          process = Runtime.getRuntime().exec("su");
          return true;
      } catch (Exception e) {
          e.printStackTrace();
          return false;
      } finally {
          if(process != null){
              try {
                  process.destroy();
              }catch (Exception e){
                  e.printStackTrace();
              }
          }
      }
  }
}
