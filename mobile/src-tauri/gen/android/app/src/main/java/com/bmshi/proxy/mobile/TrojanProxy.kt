package com.bmshi.proxy.mobile

import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationChannelCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat


class TrojanProxy : VpnService() {
  private external fun onStart(fd: Int)
  private external fun onStop()
  private lateinit var vpnFd: ParcelFileDescriptor

  private val stopReceiver = object : BroadcastReceiver() {
    override fun onReceive(context: Context?, intent: Intent?) {
      if (intent?.action == "stop") {
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
    val builder = Builder()
    for (route in resources.getStringArray(R.array.bypass_private_route)) {
      val parts = route.split("/")
      builder.addRoute(parts[0], parts[1].toInt())
    }
    builder.addAddress("10.10.10.1", 24).addDnsServer("8.8.8.8")
      .addDisallowedApplication(packageName).setSession("gfw").setMtu(MainActivity.mtu)
      .setBlocking(false)
    var vpn = builder.establish()
    if (vpn != null) {
      vpnFd = vpn
      onStart(vpn.fd)
      startForeground(830224, notifyBuilder.build())
      return START_STICKY
    } else {
      Logger.warn("establish vpn failed")
      return START_NOT_STICKY
    }
  }

  fun close() {
    Logger.info("stop vpn now in TrojanProxy")
    stopForeground(STOP_FOREGROUND_REMOVE)
    NotificationManagerCompat.from(this).deleteNotificationChannel("vpn")
    unregisterReceiver(stopReceiver)
    vpnFd.close()
    onStop()
  }

  override fun onRevoke() {
    Logger.info("revoke vpn service now")
    close()
  }
}