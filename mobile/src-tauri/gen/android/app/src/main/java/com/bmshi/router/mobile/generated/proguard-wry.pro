# THIS FILE IS AUTO-GENERATED. DO NOT MODIFY!!

# Copyright 2020-2023 Tauri Programme within The Commons Conservancy
# SPDX-License-Identifier: Apache-2.0
# SPDX-License-Identifier: MIT

-keep class com.bmshi.router.mobile.* {
  native <methods>;
}

-keep class com.bmshi.router.mobile.WryActivity {
  public <init>(...);

  void setWebView(com.bmshi.router.mobile.RustWebView);
  java.lang.Class getAppClass(...);
  int getId();
  java.lang.String getVersion();
  int startActivity(...);
}

-keep class com.bmshi.router.mobile.Ipc {
  public <init>(...);

  @android.webkit.JavascriptInterface public <methods>;
}

-keep class com.bmshi.router.mobile.RustWebView {
  public <init>(...);

  void loadUrlMainThread(...);
  void loadHTMLMainThread(...);
  void evalScript(...);
}

-keep class com.bmshi.router.mobile.RustWebChromeClient,com.bmshi.router.mobile.RustWebViewClient {
  public <init>(...);
}
