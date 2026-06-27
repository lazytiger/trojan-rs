package com.bmshi.router.mobile

import android.app.NotificationManager
import android.app.PendingIntent
import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationChannelCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import org.json.JSONArray

internal data class AllowedApplicationsResult(
  val added: List<String>,
  val missing: List<String>
)

internal fun addAllowedApplications(
  allowedApps: Iterable<String>,
  addAllowedApplication: (String) -> Unit,
  onMissingApplication: (String, PackageManager.NameNotFoundException) -> Unit = { _, _ -> }
): AllowedApplicationsResult {
  val added = mutableListOf<String>()
  val missing = mutableListOf<String>()
  val seen = LinkedHashSet<String>()

  for (rawApp in allowedApps) {
    val app = rawApp.trim()
    if (app.isEmpty() || !seen.add(app)) {
      continue
    }

    try {
      addAllowedApplication(app)
      added += app
    } catch (e: PackageManager.NameNotFoundException) {
      missing += app
      onMissingApplication(app, e)
    }
  }

  return AllowedApplicationsResult(added, missing)
}

internal fun allowedApplicationsJson(allowedApps: Iterable<String>): String {
  return JSONArray(allowedApps.toList()).toString()
}

internal fun <T> closeAndClear(
  resource: T?,
  close: (T) -> Unit,
  onError: (Exception) -> Unit
): T? {
  if (resource == null) {
    return null
  }

  try {
    close(resource)
  } catch (e: Exception) {
    onError(e)
  }
  return null
}


class TrojanProxy : VpnService() {
  private external fun onStart(fd: Int, dns: String, allowedApps: String)
  private external fun onStop()

  private external fun onNetworkChanged(available: Boolean)

  private val networkMonitorCallback = object : ConnectivityManager.NetworkCallback() {
    override fun onAvailable(network: Network) {
      setUnderlyingNetworks(arrayOf(network))
      onNetworkChanged(true)
      Logger.warn("$network is available now")
    }

    override fun onLost(network: Network) {
      setUnderlyingNetworks(arrayOf(null))
      onNetworkChanged(false)
      Logger.warn("network is lost now")
    }

    override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
      setUnderlyingNetworks(arrayOf(network))
    }
  }

  private var networkMonitorRunning = false
  private var closed = false

  private val stopReceiver = object : BroadcastReceiver() {
    override fun onReceive(context: Context?, intent: Intent?) {
      if (intent?.action == STOP_ACTION) {
        Logger.info("received stop intent")
        close()
      }
    }
  }

  private fun createNotificationBuilder(): NotificationCompat.Builder {
    val openMain = Intent(this, MainActivity::class.java)
    openMain.action = MainActivity.OPEN_CONFIG_ACTION
    openMain.flags = Intent.FLAG_ACTIVITY_NEW_TASK or
      Intent.FLAG_ACTIVITY_CLEAR_TOP or
      Intent.FLAG_ACTIVITY_SINGLE_TOP
    val pi = PendingIntent.getActivity(
      this,
      0,
      openMain,
      PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
    )
    return NotificationCompat.Builder(this, "vpn")
      .setCategory(NotificationCompat.CATEGORY_SERVICE)
      .setContentTitle("VPN服务")
      .setContentText("连接中")
      .setSmallIcon(R.mipmap.ic_launcher)
      .setContentIntent(pi)
      .setAutoCancel(false)
      .setOngoing(true)
      .setShowWhen(true)
      .setWhen(0L)
      .setSound(null)
  }

  override fun onCreate() {
    instance = this
    val filter = IntentFilter(STOP_ACTION)
    ContextCompat.registerReceiver(
      this,
      stopReceiver,
      filter,
      ContextCompat.RECEIVER_NOT_EXPORTED
    )
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    Logger.info("start vpn service now")
    val apps = intent?.getStringExtra("apps").orEmpty()
    val mtu = intent?.getIntExtra("mtu", 1500) ?: 1500
    val trustedDns = intent?.getStringExtra("trusted_dns").orEmpty()
    val notifyChannel =
      NotificationChannelCompat.Builder("vpn", NotificationManager.IMPORTANCE_LOW).setName("vpn")
        .build()
    NotificationManagerCompat.from(this).createNotificationChannel(notifyChannel)
    val notifyBuilder = createNotificationBuilder()
    MainActivity.notifyBuilder = notifyBuilder
    startForeground(NOTIFICATION_ID, notifyBuilder.build())
    Thread(Runnable {
      try {
        val allowedApps = JSONArray(apps).let { array ->
          (0 until array.length()).map { array.getString(it) }.filter { it.isNotBlank() }
        }
        if (allowedApps.isEmpty()) {
          Logger.error("selected apps is empty")
          close()
          return@Runnable
        }
        val builder = Builder()
        val manager = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = manager.activeNetwork
        if (network != null) {
          builder.setUnderlyingNetworks(arrayOf(network))
        }
        builder.addRoute("0.0.0.0", 0)
          .addAddress("10.10.10.1", 30)
          .addDnsServer("10.10.11.1")
        val allowedApplicationResult = addAllowedApplications(
          allowedApps,
          addAllowedApplication = { app -> builder.addAllowedApplication(app) },
          onMissingApplication = { app, e ->
            Logger.warn("skip missing allowed application $app: ${e.message ?: "not found"}")
          }
        )
        if (allowedApplicationResult.added.isEmpty()) {
          Logger.error("no selected apps can be added to VPN allow list")
          close()
          return@Runnable
        }
        if (allowedApplicationResult.missing.isNotEmpty()) {
          Logger.warn("missing allowed apps skipped: ${allowedApplicationResult.missing}")
        }
        builder.setSession("gfw")
          .setMtu(mtu)
          .setBlocking(false)
        val vpn = builder.establish()
        if (vpn != null) {
          Logger.info("vpn established for apps=${allowedApplicationResult.added} mtu=$mtu")
          startNetworkMonitor()
          vpnFd = vpn
          onStart(vpn.fd, "10.10.11.1", allowedApplicationsJson(allowedApplicationResult.added))
        } else {
          Logger.error("establish vpn failed")
          close()
        }
      } catch (e: Exception) {
        Logger.error("initialize vpn failed", e)
        close()
      }
    }).start()
    return START_NOT_STICKY
  }

  override fun onDestroy() {
    super.onDestroy()
    try {
      unregisterReceiver(stopReceiver)
    } catch (e: Exception) {
      Logger.info(e.toString())
    }
    close()
    if (instance === this) {
      instance = null
    }
  }

  override fun onTaskRemoved(rootIntent: Intent?) {
    Logger.info("app task removed, stop vpn service")
    close()
    super.onTaskRemoved(rootIntent)
  }

  fun close() {
    if (closed) {
      return
    }
    closed = true
    Logger.info("stop vpn now in TrojanProxy")
    onStop()
    stopNetworkMonitor()
    stopForeground(STOP_FOREGROUND_REMOVE)
    NotificationManagerCompat.from(this).deleteNotificationChannel("vpn")
    vpnFd = closeAndClear(
      vpnFd,
      close = { it.close() },
      onError = { Logger.info(it.toString()) }
    )
    stopSelf()
  }

  override fun onRevoke() {
    Logger.info("revoke vpn service now")
    close()
  }

  fun startNetworkMonitor() {
    val cm = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
    val nrb = NetworkRequest.Builder()
      .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
      .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
    if (Build.VERSION.SDK_INT == Build.VERSION_CODES.M) {
      nrb.removeCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        .removeCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)
    }
    val request = nrb.build()
    try {
      if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
        cm.registerNetworkCallback(request, networkMonitorCallback)
      } else {
        cm.requestNetwork(request, networkMonitorCallback)
      }
      networkMonitorRunning = true
    } catch (se: SecurityException) {
      Logger.warn(se.toString())
    }
  }

  fun stopNetworkMonitor() {
    val cm = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
    try {
      if (networkMonitorRunning) {
        cm.unregisterNetworkCallback(networkMonitorCallback)
        networkMonitorRunning = false
      }
    } catch (e: Exception) {
      Logger.info(e.toString())
    }
  }

  companion object {
    private var instance: TrojanProxy? = null
    private var vpnFd: ParcelFileDescriptor? = null
    const val STOP_ACTION = "com.bmshi.router.mobile.STOP_VPN"
    const val NOTIFICATION_ID = 428571

    @JvmStatic
    fun updateNotification(content: String) {
      val service = instance ?: return
      try {
        MainActivity.notifyBuilder.setContentText(content)
        if (ContextCompat.checkSelfPermission(
            service,
            Manifest.permission.POST_NOTIFICATIONS
          ) == android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
          NotificationManagerCompat.from(service)
            .notify(NOTIFICATION_ID, MainActivity.notifyBuilder.build())
        } else {
          Logger.warn("notification disabled")
        }
      } catch (e: Exception) {
        Logger.warn(e.toString())
      }
    }

    @JvmStatic
    fun syncData() {
      try {
        val fd = vpnFd?.fileDescriptor
        if (fd?.valid() == true) {
          fd.sync()
        }
      } catch (e: Exception) {
        Logger.warn(e.toString())
      }
    }
  }
}
