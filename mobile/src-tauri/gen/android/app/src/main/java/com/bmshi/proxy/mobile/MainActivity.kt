package com.bmshi.proxy.mobile

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat

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

  companion object {
    var mtu: Int = 1500
    private lateinit var instance: MainActivity
    lateinit var notifyBuilder: NotificationCompat.Builder

    private external fun initRust()

    @JvmStatic
    fun startVpn(mtu: Int) {
      Logger.info("start vpn in MainActivity")
      MainActivity.mtu = mtu
      instance.startService()
    }

    @JvmStatic
    fun shouldShowRequestPermissionRationaleNative(permission: String): Boolean {
      return instance.shouldShowRequestPermissionRationale(permission)
    }

    @JvmStatic
    fun requestPermission(permission: String) {
      instance.requestPermissionLauncher.launch(permission)
    }

    @JvmStatic
    fun checkSelfPermission(permission: String): Boolean {
      return ContextCompat.checkSelfPermission(
        instance,
        permission
      ) == PackageManager.PERMISSION_GRANTED
    }

    @JvmStatic
    fun stopVpn() {
      Logger.info("stopVpn called in MainActivity")
      val intent = Intent("stop")
      intent.setPackage(instance.packageName)
      instance.sendBroadcast(intent)
    }

    @JvmStatic
    fun updateNotification(content: String) {
      notifyBuilder.setContentText(content)
      if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)) {
        NotificationManagerCompat.from(instance).notify(830224, notifyBuilder.build())
      } else {
        Logger.info("notification disabled")
      }
    }

    @JvmStatic
    fun saveData(name: String, data: String) {
      val prefs = instance.getPreferences(MODE_PRIVATE)
      val editor = prefs.edit()
      editor.putString(name, data)
      if (editor.commit()) {
        Logger.info("saveData $name - $data")
      }
    }

    @JvmStatic
    fun loadData(name: String): String {
      val prefs = instance.getPreferences(MODE_PRIVATE)
      val value = prefs.getString(name, "").toString()
      Logger.info("loadData $name - $value")
      return value
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
  }

  private fun doActivityResult(resultCode: Int) {
    if (resultCode == RESULT_OK) {
      Logger.info("activity result is ok")
      ContextCompat.startForegroundService(this, Intent(this, TrojanProxy::class.java))
    } else {
      Logger.warn("activity result is not ok")
    }
  }
}
