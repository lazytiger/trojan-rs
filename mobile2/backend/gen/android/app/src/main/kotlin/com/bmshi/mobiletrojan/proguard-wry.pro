# THIS FILE IS AUTO-GENERATED. DO NOT MODIFY!!

# Copyright 2020-2023 Tauri Programme within The Commons Conservancy
# SPDX-License-Identifier: Apache-2.0
# SPDX-License-Identifier: MIT

-keep class com.bmshi.mobiletrojan.* {
  native <methods>;
}

-keep class com.bmshi.mobiletrojan.WryActivity {
  public <init>(...);

  void setWebView(com.bmshi.mobiletrojan.RustWebView);
  java.lang.Class getAppClass(...);
  java.lang.String getVersion();
}

-keep class com.bmshi.mobiletrojan.Ipc {
  public <init>(...);

  @android.webkit.JavascriptInterface public <methods>;
}

-keep class com.bmshi.mobiletrojan.RustWebView {
  public <init>(...);

  void loadUrlMainThread(...);
  void loadHTMLMainThread(...);
  void setAutoPlay(...);
  void setUserAgent(...);
}

-keep class com.bmshi.mobiletrojan.RustWebChromeClient,com.bmshi.mobiletrojan.RustWebViewClient {
  public <init>(...);
}