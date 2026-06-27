package com.bmshi.router.mobile

import android.content.pm.PackageManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TrojanProxyTest {
  @Test
  fun addAllowedApplicationsSkipsMissingPackagesAndKeepsValidPackages() {
    val added = mutableListOf<String>()
    val missing = mutableListOf<String>()

    val result = addAllowedApplications(
      listOf(
        "com.google.android.gms",
        "com.google.android.gsf",
        "com.android.vending"
      ),
      addAllowedApplication = { packageName ->
        if (packageName == "com.google.android.gms") {
          throw PackageManager.NameNotFoundException(packageName)
        }
        added += packageName
      },
      onMissingApplication = { packageName, _ -> missing += packageName }
    )

    assertEquals(
      listOf("com.google.android.gsf", "com.android.vending"),
      result.added
    )
    assertEquals(listOf("com.google.android.gms"), result.missing)
    assertEquals(
      listOf("com.google.android.gsf", "com.android.vending"),
      added
    )
    assertEquals(listOf("com.google.android.gms"), missing)
  }

  @Test
  fun addAllowedApplicationsIgnoresBlankAndDuplicatePackages() {
    val added = mutableListOf<String>()

    val result = addAllowedApplications(
      listOf(" com.google.android.gms ", "", "com.google.android.gms"),
      addAllowedApplication = { packageName -> added += packageName }
    )

    assertEquals(listOf("com.google.android.gms"), result.added)
    assertEquals(emptyList<String>(), result.missing)
    assertEquals(listOf("com.google.android.gms"), added)
  }

  @Test
  fun allowedApplicationsJsonSerializesActualAddedPackages() {
    assertEquals(
      "[\"com.google.android.gsf\",\"com.android.vending\"]",
      allowedApplicationsJson(
        listOf("com.google.android.gsf", "com.android.vending")
      )
    )
  }

  @Test
  fun closeAndClearDoesNothingForMissingResource() {
    var closeCalled = false

    val result = closeAndClear<String>(
      null,
      close = { closeCalled = true },
      onError = {}
    )

    assertNull(result)
    assertFalse(closeCalled)
  }

  @Test
  fun closeAndClearClosesAndClearsResource() {
    var closed = false

    val result = closeAndClear(
      "fd",
      close = { closed = true },
      onError = {}
    )

    assertNull(result)
    assertTrue(closed)
  }

  @Test
  fun closeAndClearClearsResourceWhenCloseFails() {
    var errorObserved = false

    val result = closeAndClear(
      "fd",
      close = { throw IllegalStateException("close failed") },
      onError = { errorObserved = true }
    )

    assertNull(result)
    assertTrue(errorObserved)
  }
}
