package com.bmshi.router.mobile

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import org.json.JSONArray
import org.json.JSONObject

class MainActivity : TauriActivity() {
  val requestPermissionLauncher =
    registerForActivityResult(
      ActivityResultContracts.RequestPermission()
    ) { isGranted: Boolean ->
      onPermissionResult(isGranted)
    }

  private val requestServiceLauncher =
    registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { it ->
      doActivityResult(it.resultCode)
    }

  private external fun onPermissionResult(isGranted: Boolean)
  private external fun onOpenConfigIntent()

  companion object {
    const val OPEN_CONFIG_ACTION = "com.bmshi.router.mobile.OPEN_CONFIG"
    var mtu: Int = 1500
    var selectedApp: String = ""
    var trustedDns: String = ""
    var untrustedDns: String = ""
    private lateinit var instance: MainActivity
    lateinit var notifyBuilder: NotificationCompat.Builder

    private external fun initRust()

    @JvmStatic
    fun startVpn(app: String, mtu: Int, trustedDns: String, untrustedDns: String) {
      try {
        Logger.info("start vpn in MainActivity app=$app mtu=$mtu")
        MainActivity.selectedApp = app
        MainActivity.mtu = mtu
        MainActivity.trustedDns = trustedDns
        MainActivity.untrustedDns = untrustedDns
        instance.startService()
      } catch (e: Exception) {
        Logger.warn(e.toString())
      }
    }

    @JvmStatic
    fun listInstalledApps(): String {
      val apps = JSONArray()
      return try {
        val pm = instance.packageManager
        val launcherIntent = Intent(Intent.ACTION_MAIN, null).apply {
          addCategory(Intent.CATEGORY_LAUNCHER)
        }
        val resolveInfos = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
          pm.queryIntentActivities(launcherIntent, PackageManager.ResolveInfoFlags.of(0L))
        } else {
          pm.queryIntentActivities(launcherIntent, 0)
        }
        val seen = hashSetOf<String>()
        for (resolveInfo in resolveInfos) {
          val packageName = resolveInfo.activityInfo.packageName
          if (seen.add(packageName)) {
            val app = JSONObject()
            app.put("label", resolveInfo.loadLabel(pm).toString())
            app.put("package_name", packageName)
            apps.put(app)
          }
        }
        apps.toString()
      } catch (e: Exception) {
        Logger.warn(e.toString())
        "[]"
      }
    }

    @JvmStatic
    fun shouldShowRequestPermissionRationaleNative(permission: String): Boolean {
      return try {
        instance.shouldShowRequestPermissionRationale(permission)
      } catch (e: Exception) {
        Logger.warn(e.toString())
        false
      }
    }

    @JvmStatic
    fun requestPermission(permission: String) {
      try {
        instance.requestPermissionLauncher.launch(permission)
      } catch (e: Exception) {
        Logger.warn(e.toString())
      }
    }

    @JvmStatic
    fun checkSelfPermission(permission: String): Boolean {
      return try {
        ContextCompat.checkSelfPermission(
          instance,
          permission
        ) == PackageManager.PERMISSION_GRANTED
      } catch (e: Exception) {
        Logger.warn(e.toString())
        false
      }
    }

    @JvmStatic
    fun stopVpn() {
      try {
        Logger.info("stopVpn called in MainActivity")
        val intent = Intent(TrojanProxy.STOP_ACTION)
        intent.setPackage(instance.packageName)
        instance.sendBroadcast(intent)
      } catch (e: Exception) {
        Logger.warn(e.toString())
      }
    }

    @JvmStatic
    fun updateNotification(content: String) {
      try {
        notifyBuilder.setContentText(content)
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)) {
          NotificationManagerCompat.from(instance)
            .notify(TrojanProxy.NOTIFICATION_ID, notifyBuilder.build())
        } else {
          Logger.warn("notification disabled")
        }
      } catch (e: Exception) {
        Logger.warn(e.toString())
      }
    }

    @JvmStatic
    fun saveData(name: String, data: String) {
      try {
        val prefs = instance.getPreferences(MODE_PRIVATE)
        val editor = prefs.edit()
        editor.putString(name, data)
        if (editor.commit()) {
          Logger.info("saveData $name - $data")
        }
      } catch (e: Exception) {
        Logger.warn(e.toString())
      }
    }

    @JvmStatic
    fun loadData(name: String): String {
      try {
        val prefs = instance.getPreferences(MODE_PRIVATE)
        val value = prefs.getString(name, "").toString()
        Logger.info("loadData $name - $value")
        return value
      } catch (e: Exception) {
        Logger.warn(e.toString())
        return ""
      }
    }
  }

  fun startService() {
    Logger.info("start service now")
    val intent = VpnService.prepare(this)
    if (intent != null) {
      requestServiceLauncher.launch(intent)
    } else {
      doActivityResult(RESULT_OK)
    }
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    instance = this
    initRust()
    handleOpenConfigIntent(intent)
  }

  override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    setIntent(intent)
    handleOpenConfigIntent(intent)
  }

  private fun createVpnIntent(): Intent {
    val intent = Intent(this, TrojanProxy::class.java)
    intent.putExtra("app", selectedApp)
    intent.putExtra("mtu", mtu)
    intent.putExtra("trusted_dns", trustedDns)
    intent.putExtra("untrusted_dns", untrustedDns)
    return intent
  }

  private fun handleOpenConfigIntent(intent: Intent?) {
    if (intent?.action == OPEN_CONFIG_ACTION) {
      onOpenConfigIntent()
    }
  }

  private fun doActivityResult(resultCode: Int) {
    if (resultCode == RESULT_OK) {
      Logger.info("activity result is ok")
      ContextCompat.startForegroundService(this, createVpnIntent())
    } else {
      Logger.warn("activity result is not ok")
    }
  }
}
