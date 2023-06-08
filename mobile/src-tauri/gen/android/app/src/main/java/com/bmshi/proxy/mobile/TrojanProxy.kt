package com.bmshi.proxy.mobile

import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
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


class TrojanProxy : VpnService() {
  private external fun onStart(fd: Int, gateway: String)
  private external fun onStop()

  private val networkMonitorCallback = object : ConnectivityManager.NetworkCallback() {
    override fun onAvailable(network: Network) {
      setUnderlyingNetworks(arrayOf(network))
    }

    override fun onLost(network: Network) {
      setUnderlyingNetworks(arrayOf(null))
    }

    override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
      setUnderlyingNetworks(arrayOf(network))
    }
  }

  private var networkMonitorRunning = false

  private val stopReceiver = object : BroadcastReceiver() {
    override fun onReceive(context: Context?, intent: Intent?) {
      if (intent?.action == STOP_ACTION) {
        Logger.info("received stop intent")
        close()
      }
    }
  }

  private fun createNotificationBuilder(): NotificationCompat.Builder {
    //val openMain = Intent(this, MainActivity::class.java)
    //openMain.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
    //val pi = PendingIntent.getActivity(this, 0, openMain, PendingIntent.FLAG_IMMUTABLE)
    return NotificationCompat.Builder(this, "vpn")
      .setCategory(NotificationCompat.CATEGORY_SERVICE)
      .setContentTitle("VPN服务")
      .setContentText("连接中")
      .setSmallIcon(R.mipmap.ic_launcher)
      //.setContentIntent(pi)
      .setAutoCancel(false)
      .setOngoing(true)
      .setShowWhen(true)
      .setWhen(0L)
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    Logger.info("start vpn service now")
    val notifyChannel =
      NotificationChannelCompat.Builder("vpn", NotificationManager.IMPORTANCE_HIGH).setName("vpn")
        .build()
    NotificationManagerCompat.from(this).createNotificationChannel(notifyChannel)
    val notifyBuilder = createNotificationBuilder()
    MainActivity.notifyBuilder = notifyBuilder
    val filter = IntentFilter("stop")
    registerReceiver(stopReceiver, filter)
    Thread(Runnable {
      val builder = Builder()
      val manager = getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
      val network = manager.activeNetwork
      if (network != null) {
        builder.setUnderlyingNetworks(arrayOf(network))
      }
      for (route in resources.getStringArray(R.array.bypass_china_24)) {
        val parts = route.split("/")
        builder.addRoute(parts[0], parts[1].toInt())
      }
      builder.addRoute("10.10.11.1", 32)
      builder.addAddress("10.10.10.1", 30).addDnsServer("10.10.11.1")
        .addDisallowedApplication(packageName).setSession("gfw").setMtu(MainActivity.mtu)
        .setBlocking(false)
      var vpn = builder.establish()
      if (vpn != null) {
        startNetworkMonitor()
        vpnFd = vpn
        onStart(vpn.fd, "10.10.11.1")
        startForeground(NOTIFICATION_ID, notifyBuilder.build())
      } else {
        Logger.warn("establish vpn failed")
        close()
      }
    }).start()
    return super.onStartCommand(intent, flags, startId)
  }

  fun close() {
    Logger.info("stop vpn now in TrojanProxy")
    onStop()
    stopNetworkMonitor()
    stopForeground(STOP_FOREGROUND_REMOVE)
    NotificationManagerCompat.from(this).deleteNotificationChannel("vpn")
    unregisterReceiver(stopReceiver)
    try {
      vpnFd.close()
    } catch (e: Exception) {
      Logger.info(e.toString())
    }
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
    private lateinit var vpnFd: ParcelFileDescriptor
    const val STOP_ACTION = "com.bmshi.proxy.mobile.STOP_VPN"
    const val NOTIFICATION_ID = 428571


    @JvmStatic
    fun syncData() {
      try {
        if (vpnFd.fileDescriptor.valid()) {
          vpnFd.fileDescriptor.sync()
        }
      } catch (e: Exception) {
        Logger.warn(e.toString())
      }
    }
  }
}